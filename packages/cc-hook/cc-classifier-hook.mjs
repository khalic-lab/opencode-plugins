#!/usr/bin/env node
/**
 * Claude Code PreToolUse hook — local-model command classifier.
 *
 * Same classifier as the opencode plugin, same p8 prompts, same corpus. The
 * prompts and `classify()` are IMPORTED from local-classifier.js rather than
 * copied, so `eval/smoke.mjs` and `eval/hardcases.mjs` keep measuring exactly
 * what runs here. Do not fork them.
 *
 * WHY PreToolUse AND NOT PermissionRequest
 * ----------------------------------------
 * PermissionRequest is documented as "run before permission prompt", which is
 * the event this wants. Measured on 2.1.258, it never fires headless: six
 * provocations (plain echo, network curl, credential read, scope-escalating
 * write, a forced `permissions.ask` denial, and a PreToolUse-passthrough
 * combination) produced zero invocations, while a PreToolUse hook declared in
 * the same settings.json fired every time. PreToolUse fires in every mode
 * tested: default, auto, manual, bypassPermissions.
 *
 * THE FAIL-CLOSED CONTRACT INVERTS HERE
 * -------------------------------------
 * In the opencode plugin, "do nothing" was safe: not replying left the human's
 * prompt on screen. In Claude Code, "do nothing" is an APPROVAL. Measured:
 *
 *   exit 2, any stdout (incl. empty)  -> denied
 *   exit 1, stderr set                -> ALLOWED ("non-blocking status code")
 *   exit 0, malformed JSON            -> ALLOWED
 *   hook binary missing / spawn fail  -> ALLOWED
 *   hook exceeds its `timeout`        -> ALLOWED (outcome "cancelled", never
 *                                       sets .blocked — verified live with
 *                                       timeout:2 against `sleep 8`)
 *
 * Two consequences, and they are the whole reason this file is shaped the way
 * it is:
 *
 *   1. An unhandled exception exits 1, which is a SILENT APPROVE. Every path
 *      out of this script must funnel to `deny()`. The handlers are installed
 *      on line 1 of main, before anything can throw.
 *   2. The harness `timeout` is NOT the deadline — it is a backstop that must
 *      be set LONGER than our own deadline, so we are never killed before we
 *      can exit 2. We own the clock (WATCHDOG below).
 *
 * PRECEDENCE, from the 2.1.258 decision function (`Rro`)
 * -----------------------------------------------------
 *   hook deny             -> wins unconditionally, every mode, no feature gate
 *   deny rule             -> overrides a hook allow
 *   ask rule/safety check -> overrides a hook allow, runs the full pipeline
 *   auto-mode funnel      -> gated on P("tengu_virtual_knuth", !1)
 *   otherwise             -> hook allow bypasses the permission prompt
 *
 * So the DENY path is gate-independent and the ALLOW path is a latency
 * optimization Anthropic can switch off server-side: when the gate flips, a
 * hook allow is sent through the built-in classifier anyway. You lose the
 * speedup, never correctness.
 *
 * POSTURE: WHICH WAY THE LOCAL VERDICT MAY MOVE THE DECISION
 * ---------------------------------------------------------
 * The opencode plugin approves on SAFE and leaves RISKY to the human: the
 * local model can only ADD permission, so a false SAFE is the unrecoverable
 * error and a false RISKY costs one keystroke. That is what the corpus scores
 * for — eval/hardcases reports "FALSE-SAFE (unrecoverable)" and "false-RISKY
 * (friction)". The first port inverted it (SAFE said nothing, RISKY denied),
 * which made a false RISKY a final block and left the corpus tuned for the
 * wrong error. In its first hour of shadow all 23 RISKY verdicts were reads
 * outside the project that the built-in classifier let through. Hence
 * `posture`, defaulting to "cascade": SAFE claims the decision, RISKY hands
 * the call to the built-in classifier, which is transcript-aware and better
 * informed than we are.
 *
 * ONE MODEL FOR EVERYTHING: WHAT THE FIRST DAY TAUGHT (2026-09-03)
 * ----------------------------------------------------------------
 * Since 2026-09-02 the classifier shares Flash-Next with opencode and nvim.
 * mtplx serves one generation at a time, non-preemptible, so a classifier
 * call queued behind an 80k-token opencode turn cannot win inside its 10 s
 * timeout — and the first morning it did not: 24 of 129 calls in one hour
 * timed out, each one holding the tool call for the full 10 s to say nothing.
 * Three responses, all below:
 *   - BUSY PROBE: ask the server what is in flight before sending; a long
 *     request means "say nothing now" instead of "say nothing in 10 s".
 *   - BREAKER BACKOFF: an open breaker re-closed every 60 s and each re-close
 *     bought three more 10 s waits; the cooldown now doubles per re-open.
 *   - DETACHED SHADOW: shadow only observes, so it no longer blocks the tool
 *     call at all — the worker logs the verdict and the would-be action.
 */

import { spawn } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const HOOK_NAME = "cc-local-classifier"
const HOOK_VERSION = "0.5.0"

// ---------------------------------------------------------------------------
// Exit discipline. Only exit 2 denies; everything else approves. These two
// functions are the ONLY way this process is allowed to terminate.
// ---------------------------------------------------------------------------

let exiting = false

/**
 * Block the tool call. Belt and braces: the JSON deny is emitted for the
 * documented schema path, and exit 2 forces the block regardless of whether
 * the JSON parses. With exit 2 the harness takes its block reason from
 * STDERR, not from the JSON, so the reason goes to both.
 */
function deny(reason) {
  if (exiting) return
  exiting = true
  const message = `[${HOOK_NAME}] ${reason}`
  try {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "deny",
        permissionDecisionReason: message,
      },
    }) + "\n")
  } catch {}
  try { process.stderr.write(message + "\n") } catch {}
  process.exit(2)
}

/**
 * Hand the call to the human. Claude Code renders its own permission prompt and
 * shows `reason`. Exit 0: unlike deny, this is not a block — the harness is
 * being asked to ask, and the user's answer decides.
 *
 * Used only where a deny would be merely inconvenient rather than protective:
 * a write whose sole objection is that it sits outside the session's project
 * directory. A sensitive path still denies outright, because "are you sure?"
 * is the wrong question about someone's SSH key.
 */
function askUser(reason) {
  if (exiting) return
  exiting = true
  try {
    process.stdout.write(JSON.stringify({
      hookSpecificOutput: {
        hookEventName: "PreToolUse",
        permissionDecision: "ask",
        permissionDecisionReason: `[${HOOK_NAME}] ${reason}`,
      },
    }) + "\n")
  } catch {}
  process.exit(0)
}

/**
 * Let the call proceed. `decision` null = say nothing and fall through to the
 * built-in classifier (default). "allow" = claim the decision and bypass it.
 */
function approve(decision = null, reason = "") {
  if (exiting) return
  exiting = true
  if (decision === "allow") {
    try {
      process.stdout.write(JSON.stringify({
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "allow",
          permissionDecisionReason: `[${HOOK_NAME}] ${reason}`,
        },
      }) + "\n")
    } catch {}
  }
  process.exit(0)
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const HOOK_DEFAULTS = Object.freeze({
  /** "shadow" | "enforce" | "off". Shadow logs a verdict and never blocks. */
  mode: "shadow",
  /**
   * Which way the local verdict may move the decision (see POSTURES).
   *   "cascade" — SAFE claims the call (bypasses the built-in classifier and
   *               its ~1.5 s round-trip); RISKY says nothing and the built-in
   *               classifier decides. The local model can only ADD permission:
   *               a false SAFE runs unguarded, a false RISKY costs ~0.6 s. A
   *               model failure says nothing too — the speedup is lost, nothing
   *               else. This is the opencode plugin's shape and what the corpus
   *               is scored for.
   *   "veto"    — SAFE says nothing; RISKY denies. Can only REMOVE permission:
   *               a false SAFE costs nothing, a false RISKY is a final block.
   *               Faster than cascade only when true RISKY exceeds ~14 % of
   *               calls; on this machine it is near zero and every observed
   *               RISKY was a read outside the project.
   *   "solo"    — SAFE claims, RISKY denies. Fastest; both errors are final.
   * Only the bash path (and external-directory reads, when enabled) consult
   * the posture. An in-project write or read says nothing in every posture:
   * the path rules are the only judgement made there, and claiming an allow
   * on a write would rest on a filename alone.
   */
  posture: "cascade",
  /**
   * What an OPEN CIRCUIT BREAKER does — the one policy call in this port.
   *   "deny"  — fail closed. Consistent with the plugin's invariants, but a
   *             wedged mlxctl means every command is refused and auto mode
   *             stops working until you notice.
   *   "allow" — fail open while the model is KNOWN down, logging loudly. The
   *             built-in classifier still runs, so this is a degradation to
   *             stock Claude Code, not to nothing.
   * Applies to "veto" and "solo" only. Under "cascade" every model failure
   * says nothing, breaker open or not: that posture's safety was the built-in
   * classifier's to begin with, and a deny from a latency optimizer would
   * refuse commands the model never saw. A model the busy probe found
   * occupied is treated the same way as an open breaker: known unavailable
   * before anything was sent.
   */
  breakerPolicy: "deny",
  /**
   * Classify Read/Glob/Grep whose paths leave the project. OFF here, unlike the
   * plugin, which defaults it on.
   *
   * In opencode this path sat behind a TUI ask a human could answer, so a
   * false RISKY cost one keystroke. Here a deny is final: the agent simply
   * cannot read the file. And the directory prompt names a home-directory
   * root, ~/.config and ~/.local/share as RISKY *by name*, which on this
   * machine is the chezmoi dotfile tree and ~/.claude/settings.json. Measured
   * 2026-09-02, all three deny in enforce:
   *   Read ~/.claude/settings.json                    -> RISKY
   *   Read ~/.local/share/chezmoi/dot_gitconfig.tmpl  -> RISKY
   *   Grep ~/.config                                  -> RISKY
   * That is the classifier working as specified and still being wrong for this
   * harness.
   *
   * Turning it off does NOT leave reads unguarded: an uncovered read says
   * nothing and falls through to the built-in classifier, which is
   * transcript-aware and better suited to judging a read than a stateless
   * model is. The bash path — where the damage is — stays covered either way.
   */
  externalDirectory: false,
  /** Consecutive classifier failures before the breaker opens. */
  breakerThreshold: 3,
  /**
   * How long the breaker stays open the FIRST time. Every re-open without a
   * success in between doubles it (see loadBreaker), up to the cap below. At
   * a flat 60 s the breaker re-closed every minute of a 25-minute busy spell
   * and each re-close cost the next three tool calls 10 s apiece.
   */
  breakerCooldownMs: 60_000,
  /** Cap for that backoff. */
  breakerMaxCooldownMs: 300_000,
  /**
   * Skip the model when it is visibly busy. Before sending, the hook asks the
   * server's flight list (mtplx `GET /v1/mtplx/flight`) what it is serving.
   * An in-flight request with at least this many prompt tokens means the
   * classifier's turn cannot come inside its timeout — mtplx runs one
   * generation at a time, non-preemptible, and prefill alone is ~2.6k tok/s
   * hot — so the hook says nothing at once instead of waiting 10 s to say the
   * same thing. 0 disables the probe. A server without the endpoint, or a
   * probe that fails or times out, is never "busy": the probe must not be a
   * reason to skip classification on its own.
   */
  busyPromptTokens: 6000,
  /** How long the busy probe may take before it is abandoned (ms). */
  busyProbeMs: 400,
  /**
   * In shadow, run the classification DETACHED: the hook exits at once and
   * the worker logs the verdict and the would-be action on its own, under the
   * same join keys. Shadow's job is to observe, and blocking a tool call for
   * a verdict nobody acts on was pure latency — every timeout on the first
   * shared-model morning held the session 10 s for one log line. Set false
   * to make shadow block exactly as enforce would, for measuring end-to-end
   * feel. Ignored in enforce, where the hook has to wait by definition.
   */
  shadowDetached: true,
  /**
   * OUR deadline for the whole hook, watchdog included. Must stay comfortably
   * under the `timeout` declared in settings.json — that one fails OPEN, so it
   * must never be the thing that fires.
   */
  deadlineMs: 12_000,
  /**
   * Extra directories to treat as project roots, on top of the built-in three
   * in ccOwnRoot. A target under one of these is judged with that root as its
   * project: the boundary rule ("outside the project directory") stops firing,
   * and NOTHING else changes — SENSITIVE_PATH_PATTERNS still apply inside it,
   * so listing a root cannot unlock an ~/.ssh or a shell profile within it.
   *
   * This exists because a session's project is wherever it was started, and
   * real work spans trees: a session in ~/.config editing the spike repo had
   * every write denied as external, which is the rule working as specified and
   * still wrong for the task.
   *
   * Read ONLY from ~/.config/<HOOK_NAME>/config.json. resolveHookConfig reads
   * no project layer by design, so a cloned repo cannot widen its own
   * boundary — adding a root stays a deliberate act by the user, in a file
   * only the user writes. `~` is expanded; relative paths are rejected.
   */
  extraRoots: [],
  /**
   * What a write does when its ONLY objection is that it lands outside the
   * session's project directory.
   *   "deny" — refuse it (the original behaviour).
   *   "ask"  — hand it to the human via Claude Code's own permission prompt,
   *            and if they approve, remember that folder so the question is
   *            asked once per folder rather than once per file.
   * A sensitive path (credentials, shell/system config, code that runs on its
   * own) is never askable and always denies, inside a declared root or not.
   */
  outsideProjectAction: "deny",
  /**
   * Where an approved folder is remembered. Kept apart from config.json on
   * purpose: extraRoots is what you declared by hand, this is what you agreed
   * to in a prompt. Two files means you can read back what the hook granted
   * itself, and delete this one without losing your own settings.
   */
  rememberedRootsFile: path.join(os.homedir(), ".local", "state", HOOK_NAME, "remembered-roots.json"),
  /** Where this hook's JSONL goes. Deliberately NOT the opencode log dir: the */
  /** analyzer must not blend two harnesses into one gate. */
  logDir: path.join(os.homedir(), ".local", "share", HOOK_NAME, "logs"),
  /** Breaker state file. Hook processes are ephemeral, so it lives on disk. */
  stateDir: path.join(os.homedir(), ".local", "state", HOOK_NAME),
})

/** Smallest busy threshold that cannot be tripped by a classifier request of our own. */
const BUSY_PROMPT_TOKENS_FLOOR = 5000

/** Tool names as Claude Code spells them (not opencode's lowercase set). */
const CC_BASH_TOOLS = new Set(["Bash", "BashOutput"])
const CC_WRITE_TOOLS = new Set(["Write", "Edit", "NotebookEdit"])
const CC_READ_TOOLS = new Set(["Read", "Glob", "Grep"])

/**
 * What each posture says on each classifier outcome. FAIL is a timeout, an
 * unreachable model, an open breaker, a busy model, or the hook's own
 * deadline. Only the bash path and the external-directory read path consult
 * this table; an in-project write or read says nothing in every posture. See
 * HOOK_DEFAULTS.posture.
 */
const POSTURES = Object.freeze({
  cascade: Object.freeze({ SAFE: "allow", RISKY: "pass", FAIL: "pass" }),
  veto:    Object.freeze({ SAFE: "pass",  RISKY: "deny", FAIL: "deny" }),
  solo:    Object.freeze({ SAFE: "allow", RISKY: "deny", FAIL: "deny" }),
})

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")) } catch { return null }
}

function resolveHome(p) {
  if (p === "~") return os.homedir()
  return p.startsWith("~/") ? path.join(os.homedir(), p.slice(2)) : p
}

/**
 * The Claude Code-owned root a write target falls under, or null.
 *
 * The harness itself tells the model to write to two places that sit outside
 * every project by construction: the per-session scratchpad under
 * /private/tmp/claude-<uid>/, the per-project memory under
 * ~/.claude/projects/<slug>/memory/, and plan files under ~/.claude/plans/.
 * The p7 bash prompt names the same three; this is the deterministic half,
 * for Write/Edit and for the read path when it is on. The directory prompt
 * does NOT name them: tried and measured 2026-09-02, the model generalised
 * "memory area" to all of ~/.claude. The plugin's boundary rule was written
 * for opencode, which has neither. In its first hour of shadow this hook
 * logged 16 would_deny rows for exactly those two — every artifact edit of
 * another session and this project's memory file — and in enforce each would
 * have been a hard deny in every posture. A target under one of these roots
 * is judged with that root as its project: the sensitive-path patterns still
 * apply, the boundary rule does not. The rest of ~/.claude stays outside —
 * settings.json is what enables this hook.
 */
/**
 * Validate user-declared extra roots. A root that aliases HOME, the filesystem
 * root, or a system root would turn the boundary rule off for most of the disk,
 * so those are rejected rather than clamped — a silently narrowed root would
 * look like it worked. Relative paths are rejected because the hook's cwd is
 * whatever Claude Code happened to spawn it in.
 */
function normalizeExtraRoots(value, problems) {
  if (value === undefined) return []
  if (!Array.isArray(value)) { problems.push("invalid extraRoots (not an array)"); return [] }
  const home = os.homedir()
  const forbidden = new Set(["/", home, "/etc", "/usr", "/var", "/System", "/Library", "/bin", "/sbin", "/opt"])
  const out = []
  for (const entry of value) {
    if (typeof entry !== "string" || !entry.trim()) { problems.push(`invalid extraRoots entry ${JSON.stringify(entry)}`); continue }
    const abs = path.resolve(resolveHome(entry.trim()))
    if (!path.isAbsolute(abs)) { problems.push(`extraRoots entry ${entry} is not absolute; ignored`); continue }
    if (forbidden.has(abs)) { problems.push(`extraRoots entry ${entry} resolves to ${abs}, which is too broad; ignored`); continue }
    // A root at or above HOME would cover the whole home tree.
    if (home === abs || home.startsWith(abs.endsWith("/") ? abs : abs + "/")) {
      problems.push(`extraRoots entry ${entry} contains the home directory; ignored`)
      continue
    }
    out.push(abs)
  }
  return out
}

/**
 * The folder we would offer to remember for `abs`: the nearest ancestor holding
 * a .git, else the file's own directory. Asking about a repo rather than a
 * single directory is what makes this once-per-project instead of once-per-file,
 * and a repo root is a boundary the user already drew.
 */
function candidateRootFor(abs) {
  let dir = path.dirname(abs)
  const home = os.homedir()
  for (let i = 0; i < 40 && dir && dir !== "/" && dir !== home; i++) {
    try {
      if (fs.existsSync(path.join(dir, ".git"))) return dir
    } catch {}
    const up = path.dirname(dir)
    if (up === dir) break
    dir = up
  }
  return path.dirname(abs)
}

/** Roots the user approved at a prompt. Never written by hand; see HOOK_DEFAULTS. */
function loadRememberedRoots(cfg) {
  const data = readJson(cfg.rememberedRootsFile)
  return normalizeExtraRoots(Array.isArray(data?.roots) ? data.roots : [], [])
}

/** Add one approved root. Idempotent; failure to persist is logged, never fatal. */
function rememberRoot(cfg, root) {
  const current = loadRememberedRoots(cfg)
  if (current.includes(root)) return { added: false, roots: current }
  const roots = [...current, root]
  fs.mkdirSync(path.dirname(cfg.rememberedRootsFile), { recursive: true, mode: 0o700 })
  fs.writeFileSync(cfg.rememberedRootsFile, JSON.stringify({ roots }, null, 2) + "\n", { mode: 0o600 })
  return { added: true, roots }
}


/**
 * Park the folder we offered, against the tool call we offered it for.
 *
 * PreToolUse cannot see the user's answer — the process is gone before the
 * prompt is drawn. PostToolUse only fires if the call actually ran, which for
 * an "ask" means the human approved it. Matching the two by tool_use_id is what
 * makes "remember this folder" mean "remember the folder the user just said yes
 * to", and not "remember any folder a write happened to touch".
 *
 * Entries expire: an ask the user declined is never collected, so without a TTL
 * the file would grow forever with folders nobody approved.
 */
const ASK_TTL_MS = 10 * 60_000
const ASK_MAX = 50

function parkAsk(cfg, toolUseId, root) {
  if (!toolUseId || !root) return
  try {
    const file = path.join(cfg.stateDir, "pending-asks.json")
    const now = Date.now()
    const prev = readJson(file)
    const kept = (Array.isArray(prev?.asks) ? prev.asks : [])
      .filter((a) => a && typeof a.id === "string" && now - (a.at ?? 0) < ASK_TTL_MS && a.id !== toolUseId)
      .slice(-ASK_MAX)
    kept.push({ id: toolUseId, root, at: now })
    fs.mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 })
    fs.writeFileSync(file, JSON.stringify({ asks: kept }, null, 2) + "\n", { mode: 0o600 })
  } catch {}
}

/** Take back a parked ask, removing it. Returns the root, or null. */
function claimAsk(cfg, toolUseId) {
  if (!toolUseId) return null
  try {
    const file = path.join(cfg.stateDir, "pending-asks.json")
    const now = Date.now()
    const asks = (readJson(file)?.asks ?? []).filter((a) => a && now - (a.at ?? 0) < ASK_TTL_MS)
    const hit = asks.find((a) => a.id === toolUseId)
    if (!hit) return null
    const rest = asks.filter((a) => a.id !== toolUseId)
    fs.writeFileSync(file, JSON.stringify({ asks: rest }, null, 2) + "\n", { mode: 0o600 })
    return hit.root
  } catch {
    return null
  }
}

function ccOwnRoot(abs, extraRoots = []) {
  const under = (root) => abs === root || abs.startsWith(root.endsWith("/") ? root : root + "/")
  // User-declared roots first: an explicit choice outranks the built-ins, and
  // returning the DECLARED root (not a built-in that happens to also match)
  // keeps judgeWritePath's boundary anchored where the user said.
  for (const root of extraRoots) if (under(root)) return root
  const uid = typeof process.getuid === "function" ? process.getuid() : null
  if (uid !== null) {
    for (const root of [`/private/tmp/claude-${uid}`, `/tmp/claude-${uid}`]) if (under(root)) return root
  }
  const plans = path.join(os.homedir(), ".claude", "plans")
  if (under(plans)) return plans
  const projects = path.join(os.homedir(), ".claude", "projects")
  if (under(projects)) {
    const rest = abs.slice(projects.length + 1).split("/") // [slug, "memory", ...]
    if (rest.length >= 3 && rest[1] === "memory") return path.join(projects, rest[0], "memory")
  }
  return null
}

/**
 * Mode and deadline, resolved WITHOUT importing anything.
 *
 * This exists because of a bug the exit-discipline battery caught: with the
 * mode resolved after `import()`, a broken install (missing module, syntax
 * error in local-classifier.js) crashed while the fatal handler was still
 * unconditionally fail-closed, so a hook configured for SHADOW blocked every
 * command in the session. Shadow observes; it must never block, least of all
 * because of its own installation. Reading two files first costs microseconds
 * and makes the crash handler correct from the start.
 */
function peekMode(env = process.env) {
  const out = { mode: HOOK_DEFAULTS.mode, posture: HOOK_DEFAULTS.posture, deadlineMs: HOOK_DEFAULTS.deadlineMs }
  // Same layer order as resolveHookConfig: opencode user file, then the
  // hook's own file, then env. A disagreement here would be worse than a
  // wrong value — the crash handler would fail closed while the real run
  // failed open, or the reverse.
  try {
    const oc = readJson(path.join(os.homedir(), ".config", "opencode", "local-classifier.json"))
    if (oc && typeof oc.mode === "string") out.mode = oc.mode
    const layer = readJson(path.join(os.homedir(), ".config", HOOK_NAME, "config.json"))
    if (layer && typeof layer.mode === "string") out.mode = layer.mode
    if (layer && typeof layer.posture === "string") out.posture = layer.posture
    if (layer && Number.isFinite(layer.deadlineMs) && layer.deadlineMs > 0) out.deadlineMs = layer.deadlineMs
  } catch {}
  if (typeof env.OPENCODE_LOCAL_CLASSIFIER_MODE === "string") out.mode = env.OPENCODE_LOCAL_CLASSIFIER_MODE
  if (typeof env.CC_CLASSIFIER_MODE === "string") out.mode = env.CC_CLASSIFIER_MODE
  if (typeof env.CC_CLASSIFIER_POSTURE === "string") out.posture = env.CC_CLASSIFIER_POSTURE
  if (!["shadow", "enforce", "off"].includes(out.mode)) out.mode = HOOK_DEFAULTS.mode
  if (!Object.hasOwn(POSTURES, out.posture)) out.posture = HOOK_DEFAULTS.posture
  return out
}

/**
 * Layers: the classifier's own defaults (endpoint/model/timeout/prompts) come
 * from local-classifier.js so both harnesses point at one model by one config;
 * hook-specific keys layer on top from ~/.config/<HOOK_NAME>/config.json and
 * the environment.
 *
 * The project layer is deliberately NOT read. In opencode a project file could
 * only LOWER the mode; here the hook is the only fail-closed control in the
 * path, and a cloned repo must not be able to touch it at all.
 */
function resolveHookConfig(internals, env = process.env) {
  const base = internals.resolveConfig({ worktree: null, env })
  const problems = [...base.problems]
  const merged = { ...HOOK_DEFAULTS, mode: base.config.mode }
  const userFile = path.join(os.homedir(), ".config", HOOK_NAME, "config.json")
  const layer = readJson(userFile)
  if (layer && typeof layer === "object") {
    for (const [k, v] of Object.entries(layer)) {
      if (Object.hasOwn(HOOK_DEFAULTS, k)) merged[k] = v
      else problems.push(`unknown key ${k}`)
    }
  }
  if (typeof env.CC_CLASSIFIER_MODE === "string") merged.mode = env.CC_CLASSIFIER_MODE
  if (typeof env.CC_CLASSIFIER_POSTURE === "string") merged.posture = env.CC_CLASSIFIER_POSTURE
  // Test hooks: the battery flips these per case without a config file.
  if (typeof env.CC_CLASSIFIER_SHADOW_DETACHED === "string") merged.shadowDetached = env.CC_CLASSIFIER_SHADOW_DETACHED !== "0"
  if (typeof env.CC_CLASSIFIER_BUSY_PROMPT_TOKENS === "string") merged.busyPromptTokens = Number(env.CC_CLASSIFIER_BUSY_PROMPT_TOKENS)

  // Validate field by field; every miss degrades to the default rather than
  // crashing, because crashing exits 1 and exit 1 approves.
  if (!["shadow", "enforce", "off"].includes(merged.mode)) {
    problems.push(`invalid mode ${JSON.stringify(merged.mode)}`); merged.mode = "shadow"
  }
  if (typeof merged.posture !== "string" || !Object.hasOwn(POSTURES, merged.posture)) {
    problems.push(`invalid posture ${JSON.stringify(merged.posture)}`); merged.posture = HOOK_DEFAULTS.posture
  }
  if (!["deny", "allow"].includes(merged.breakerPolicy)) {
    problems.push(`invalid breakerPolicy`); merged.breakerPolicy = HOOK_DEFAULTS.breakerPolicy
  }
  for (const k of ["breakerThreshold", "breakerCooldownMs", "breakerMaxCooldownMs", "deadlineMs", "busyProbeMs"]) {
    if (!Number.isFinite(merged[k]) || merged[k] <= 0) { problems.push(`invalid ${k}`); merged[k] = HOOK_DEFAULTS[k] }
  }
  // 0 is "off". Anything else must clear the classifier's OWN request size
  // (the p8 prompt is ~3.3k tokens, a subject up to ~1.1k more): below that,
  // a sibling hook's classification in flight reads as "busy" and under veto
  // or solo the hook denies commands because it is using the model itself.
  if (!Number.isFinite(merged.busyPromptTokens) || merged.busyPromptTokens < 0
      || (merged.busyPromptTokens > 0 && merged.busyPromptTokens < BUSY_PROMPT_TOKENS_FLOOR)) {
    problems.push(`invalid busyPromptTokens ${JSON.stringify(merged.busyPromptTokens)} (0 = off, otherwise at least ${BUSY_PROMPT_TOKENS_FLOOR})`)
    merged.busyPromptTokens = HOOK_DEFAULTS.busyPromptTokens
  }
  for (const k of ["externalDirectory", "shadowDetached"]) {
    if (typeof merged[k] !== "boolean") { problems.push(`invalid ${k}`); merged[k] = HOOK_DEFAULTS[k] }
  }
  for (const k of ["logDir", "stateDir"]) {
    if (typeof merged[k] !== "string" || !merged[k]) { problems.push(`invalid ${k}`); merged[k] = HOOK_DEFAULTS[k] }
  }
  merged.extraRoots = normalizeExtraRoots(merged.extraRoots, problems)
  if (!["deny", "ask"].includes(merged.outsideProjectAction)) {
    problems.push(`invalid outsideProjectAction`); merged.outsideProjectAction = HOOK_DEFAULTS.outsideProjectAction
  }
  if (typeof merged.rememberedRootsFile !== "string" || !merged.rememberedRootsFile) {
    problems.push("invalid rememberedRootsFile"); merged.rememberedRootsFile = HOOK_DEFAULTS.rememberedRootsFile
  }
  // The classifier call keeps its own timeout, but it must finish inside our
  // deadline or the watchdog fires first and we lose the verdict's reason.
  // `mode` is re-stamped from the layered value: base.config.mode is the
  // opencode file's, and the logger writes config.mode on every line. Left
  // alone, a shadow run logged mode:"enforce" on every would_* row.
  const classifier = { ...base.config, mode: merged.mode, logDir: merged.logDir }
  // Headroom for import, stdin and the log write. Without it the watchdog
  // fires before the classifier's own timeout returns, the verdict's reason
  // is lost, and under cascade a slow model looked like a hook failure.
  const headroom = 2000
  const cap = Math.max(500, merged.deadlineMs - headroom)
  if (classifier.timeoutMs > cap) {
    problems.push(`timeoutMs ${classifier.timeoutMs} leaves under ${headroom} ms before deadlineMs ${merged.deadlineMs}; clamped to ${cap}`)
    classifier.timeoutMs = cap
  }
  return { hook: merged, classifier, problems }
}

// ---------------------------------------------------------------------------
// File-backed circuit breaker. `createBreaker` in the plugin holds its counter
// in a closure, which works there because the plugin is one long-lived process.
// A hook is a fresh process per tool call, so the counter goes on disk.
// Failure to read or write the state file is never fatal: a breaker that
// cannot remember is a breaker that never opens, which is the same as not
// having one, and that must not be a reason to block or crash.
//
// Backoff: `opens` counts re-opens without a success in between, and the
// cooldown doubles with it (60 s, 120 s, 240 s, capped). A success from any
// process that shares the file — a hook call or the launchd `--warm` — resets
// everything, so the breaker closes the moment the model answers again rather
// than on a timer that was set before anyone knew how long the trouble would
// last.
// ---------------------------------------------------------------------------

function cooldownFor(cfg, opens) {
  const n = Number.isFinite(opens) && opens > 0 ? opens : 1
  return Math.min(cfg.breakerMaxCooldownMs, cfg.breakerCooldownMs * 2 ** (n - 1))
}

function loadBreaker(cfg, now = Date.now) {
  const file = path.join(cfg.stateDir, "breaker.json")
  const raw = readJson(file) ?? {}
  const failures = Number.isFinite(raw.consecutiveFailures) && raw.consecutiveFailures > 0 ? raw.consecutiveFailures : 0
  const openedAt = Number.isFinite(raw.openedAt) && raw.openedAt > 0 ? raw.openedAt : 0
  const opens = Number.isFinite(raw.opens) && raw.opens > 0 ? raw.opens : 0
  const cooldownMs = cooldownFor(cfg, opens)
  // An openedAt in the future (clock jump, hand-edited file) counts as closed:
  // otherwise `now - openedAt` is negative, always under the cooldown, and the
  // breaker stays open until the clock catches up — under veto that is every
  // command denied indefinitely.
  const since = now() - openedAt
  const open = openedAt > 0 && since >= 0 && since < cooldownMs
  const write = (next) => {
    try {
      fs.mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 })
      fs.writeFileSync(file, JSON.stringify(next), { mode: 0o600 })
    } catch {}
    return next
  }
  return {
    file,
    open,
    state: { consecutiveFailures: failures, openedAt, opens, cooldownMs },
    /** Record one outcome; returns the state written. `openedAt` set = it (re)opened now. */
    record(failed) {
      if (!failed) return write({ consecutiveFailures: 0, openedAt: 0, opens: 0 })
      const n = failures + 1
      const reopen = n >= cfg.breakerThreshold
      return write({ consecutiveFailures: n, openedAt: reopen ? now() : 0, opens: reopen ? opens + 1 : opens })
    },
  }
}

// ---------------------------------------------------------------------------
// Busy probe. mtplx exposes what it is serving at GET /v1/mtplx/flight; the
// `active` rows carry prompt_tokens, phase and elapsed_s. One local HTTP call
// of a few milliseconds, and the answer to "would waiting be pointless?".
// ---------------------------------------------------------------------------

/**
 * `{ busy, probe }`: `busy` is the longest in-flight request at or above
 * `busyPromptTokens`, or null; `probe` says how that answer was reached —
 * "off", "free", "busy", or "unavailable:<why>" when the endpoint is missing,
 * refuses, or times out. Null busy on every error is deliberate: the probe is
 * a shortcut, never a gate. The `probe` string goes on the classification
 * row so a probe that silently never works (a proxy that does not forward
 * the path, say) is one grep away from being noticed rather than looking
 * like a model that was never busy.
 */
async function probeBusy(classifier, cfg, fetchImpl = fetch) {
  if (!(cfg.busyPromptTokens > 0)) return { busy: null, probe: "off" }
  // With a cascade configured this asks about the SECONDARY's server, not the
  // primary's. The probe exists because mtplx serves one generation at a time
  // and a classifier call queued behind a long turn cannot win inside its
  // timeout — and mtplx is where the secondary runs. The primary is a
  // single-tenant mlx_lm.server with no flight list at all, so probing it
  // would answer "unavailable:http_404" forever and never skip anything.
  //
  // A busy secondary skips the whole cascade, including a primary that might
  // have answered certain-SAFE on its own. That is the conservative reading
  // and it is deliberate: the stage that decides the hard cases is the one
  // that has to be available for the answer to mean what it usually means.
  const target = classifier.cascade?.secondary?.endpoint ?? classifier.endpoint
  const url = `${String(target ?? "").replace(/\/+$/, "")}/mtplx/flight`
  try {
    const res = await fetchImpl(url, { signal: AbortSignal.timeout(cfg.busyProbeMs) })
    if (!res.ok) return { busy: null, probe: `unavailable:http_${res.status}` }
    const body = await res.json()
    const active = Array.isArray(body?.active) ? body.active : null
    if (!active) return { busy: null, probe: "unavailable:no_active_list" }
    let worst = null
    for (const a of active) {
      const tokens = Number(a?.prompt_tokens) || 0
      if (tokens >= cfg.busyPromptTokens && (!worst || tokens > worst.prompt_tokens)) {
        worst = {
          prompt_tokens: tokens,
          phase: typeof a?.phase === "string" ? a.phase : null,
          elapsed_s: Number(a?.elapsed_s) || 0,
        }
      }
    }
    return worst ? { busy: { ...worst, active: active.length }, probe: "busy" } : { busy: null, probe: "free" }
  } catch (e) {
    const why = e?.name === "TimeoutError" || e?.name === "AbortError" ? "timeout" : String(e?.code ?? e?.name ?? "error").slice(0, 40)
    return { busy: null, probe: `unavailable:${why}` }
  }
}

// ---------------------------------------------------------------------------
// The decision table as a pure function, so the hook process and a detached
// worker compute the same would-be action from the same result.
// ---------------------------------------------------------------------------

/**
 * Map a classifier outcome onto a decision. Verdicts follow the posture. A
 * failure is where the postures part ways: under cascade the hook only ever
 * adds permission, so a model that is down, busy or slow costs the speedup and
 * nothing else — say nothing, the built-in classifier decides. Under veto and
 * solo the deny is what the posture is for, so a failure denies (fail closed),
 * except a KNOWN-unavailable model (open breaker, busy probe) with
 * breakerPolicy "allow".
 */
function planFor(result, cfg, riskyPrefix = "classified RISKY") {
  const map = POSTURES[cfg.posture] ?? POSTURES.cascade
  if (result.verdict === "SAFE") return { outcome: map.SAFE, why: "classified SAFE", extra: { verdict: "SAFE" } }
  if (result.verdict === "RISKY") {
    const tail = map.RISKY === "pass" ? " — left to the built-in classifier" : ""
    return { outcome: map.RISKY, why: `${riskyPrefix}: ${result.reason ?? ""}${tail}`, extra: { verdict: "RISKY" } }
  }
  const extra = { verdict: null, failure: result.failure }
  if (result.busy) extra.busy = result.busy
  const known = result.failure === "breaker_open" || result.failure === "busy"
  const what = result.failure === "breaker_open"
    ? "classifier down (breaker open)"
    : result.failure === "busy"
      ? `classifier busy (a ${result.busy?.prompt_tokens ?? "?"}-token request is in flight)`
      : `classifier failed (${result.failure})`
  if (map.FAIL === "pass") return { outcome: "pass", why: `${what} — left to the built-in classifier`, extra }
  if (known && cfg.breakerPolicy === "allow") {
    return { outcome: "pass", why: `${what} — degraded to the built-in classifier`, extra }
  }
  return { outcome: "deny", why: what, extra }
}

/** The one classification log row, written by whichever process has the result. */
function logClassification(log, I, base, kind, subject, classifier, result, via, probe = null) {
  log.log("classification", {
    ...base, permission: kind, subject,
    endpoint: classifier.endpoint, model: classifier.model,
    prompt_version: I.PROMPT_VERSION,
    verdict: result.verdict, reason: result.reason, failure: result.failure,
    latency_ms: result.latencyMs, raw_output: I.truncated(result.raw, 4000),
    session: result.session ?? null, streamed: Boolean(result.streamed), via,
    // The cascade's stage record, from whichever process holds the result:
    // the worker sends these back on its decision line, so a row written here
    // says the same thing as one written there.
    ...(I.stageFields ? I.stageFields(result) : {}),
    ...(probe ? { probe } : {}),
  })
}

// ---------------------------------------------------------------------------

/**
 * `--warm`: re-send a throwaway classification purely to keep the model's
 * cached prompt prefix hot, then exit.
 *
 * The plugin does this on an in-process timer (`warmIntervalMs`). A hook is a
 * fresh process per tool call, so nothing in it can hold a timer, and the
 * keepalive has to come from outside — see com.khalic.cc-classifier-warm.plist.
 *
 * This is not an optimization. Measured on 2026-09-02, the first hook call
 * after a cold prefix took longer than the whole 10s classifier timeout and
 * returned `failure: "timeout"`; in enforce that denies a command that was
 * never classified. Warm, the same call is ~450-550ms end to end including
 * node startup. The prefix is evicted by other traffic on the model server, so
 * this repeats rather than running once.
 *
 * The warm also reports to the breaker: a success closes an open breaker at
 * once, a failure counts like any other. That is what makes the backoff safe
 * to lengthen — the breaker no longer has to guess when the model is back.
 */
async function warm() {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const modulePath = process.env.CC_CLASSIFIER_MODULE
    ?? path.resolve(here, "..", "local-classifier", "local-classifier.js")
  const { LocalClassifier } = await import(modulePath)
  const I = LocalClassifier.internals
  const { hook: cfg, classifier } = resolveHookConfig(I, process.env)
  const started = Date.now()
  // The warm is not exempt from the flight list: during the very congestion
  // the probe exists for, it would otherwise queue a full prefill behind the
  // long request every four minutes and then book the timeout as a failure.
  // A busy model is not evidence the warm failed, so nothing is recorded.
  const { busy, probe } = await probeBusy(classifier, cfg)
  if (busy) {
    I.createLogger({ ...classifier, logDir: cfg.logDir }).log("warm", {
      harness: "claude-code", hook_version: HOOK_VERSION,
      endpoint: classifier.endpoint, model: classifier.model,
      prompt_version: I.PROMPT_VERSION, skipped: "busy", busy, probe,
    })
    process.stdout.write(`warm busy ${Date.now() - started}ms (${busy.prompt_tokens} tokens in flight)\n`)
    process.exit(0)
  }
  // The whole answer, so the warm covers the reason's tokens too.
  const first = await I.classify({ kind: "bash", subject: "true", config: classifier, projectDir: null })
  const result = I.withReason ? await I.withReason(first) : first
  const breaker = loadBreaker(cfg)
  const next = breaker.record(Boolean(result.failure))
  const log = I.createLogger({ ...classifier, logDir: cfg.logDir })
  if (result.failure && next.openedAt) {
    log.log("breaker.open", { harness: "claude-code", hook_version: HOOK_VERSION, source: "warm",
      after_consecutive_failures: next.consecutiveFailures, cooldown_ms: cooldownFor(cfg, next.opens) })
  }
  log.log("warm", {
    harness: "claude-code", hook_version: HOOK_VERSION,
    endpoint: classifier.endpoint, model: classifier.model,
    prompt_version: I.PROMPT_VERSION,
    verdict: result.verdict, failure: result.failure, latency_ms: result.latencyMs,
    breaker_was_open: breaker.open, breaker_closed: breaker.open && !result.failure, probe,
  })
  process.stdout.write(`warm ${result.failure ?? result.verdict} ${Date.now() - started}ms\n`)
  process.exit(result.failure ? 1 : 0)
}

async function readStdin() {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString("utf8")
}

// ---------------------------------------------------------------------------
// The model call runs in a DETACHED WORKER, not in the hook process.
//
// classify() streams the answer and settles on its first line, while the
// REASON line is still being written (~450 ms more on Flash-Next, measured
// 2026-09-03). The opencode plugin can just keep reading; this process cannot:
// Claude Code takes the decision from the hook's exit, so the hook has to be
// gone the moment the verdict is known, and a process that is gone cannot
// finish reading a stream. So the request is made by a child in its own
// process group. It writes exactly one line to its stdout — the decision — and
// never writes there again; the parent decides on that line and exits; the
// child goes on reading, writes the tail to the log under the same join keys,
// and exits on its own. Node startup for the child is ~50 ms, against ~400 ms
// of reason-writing it takes off the critical path.
//
// In DETACHED SHADOW the parent does not even wait for the line: the job
// carries `detached: true`, the worker writes the classification row, the
// breaker state and the would-be action itself, and the parent has already
// said nothing and exited.
//
// On the attached path the fail-closed shape is unchanged: any way the worker
// can fail to deliver a line (spawn error, crash, bad output, silence) is a
// classifier FAILURE under the posture table, exactly like a timeout. On the
// detached path nothing is decided, so the only thing a dead worker can lose
// is its log rows; the parent's `classification.dispatched` row keeps the
// count honest. CC_CLASSIFIER_INPROCESS=1 keeps the old in-process call for
// the eval and for debugging.
// ---------------------------------------------------------------------------

/** The worker side: one classification, decision on stdout, tail in the log. */
async function worker() {
  // The parent is gone by the time the tail lands; a closed pipe must not be
  // what kills the log write.
  process.stdout.on("error", () => {})
  const here = path.dirname(fileURLToPath(import.meta.url))
  const modulePath = process.env.CC_CLASSIFIER_MODULE
    ?? path.resolve(here, "..", "local-classifier", "local-classifier.js")
  const { LocalClassifier } = await import(modulePath)
  const I = LocalClassifier.internals
  const { hook: cfg, classifier } = resolveHookConfig(I, process.env)
  // Whatever happens, this process ends: the verdict's clock, the tail's
  // clock, and a margin for the log write.
  setTimeout(() => process.exit(0), classifier.timeoutMs + (classifier.tailTimeoutMs ?? 5000) + 2000)
  const say = (rec) => { try { process.stdout.write(JSON.stringify(rec) + "\n") } catch {} }
  let job
  try {
    job = JSON.parse(await readStdin())
    if (!job || typeof job.subject !== "string" || typeof job.kind !== "string") throw new Error("bad job")
  } catch {
    say({ verdict: null, reason: null, raw: null, failure: "worker_bad_job" })
    return process.exit(0)
  }
  const result = await I.classify({ kind: job.kind, subject: job.subject, config: classifier, projectDir: job.projectDir ?? null })
  // RISKY waits for its reason: it is what the posture shows to the agent or
  // leaves in the built-in classifier's lap, and RISKY is the rare path.
  let latencyMs = result.latencyMs
  if (result.verdict === "RISKY" && result.rest) latencyMs = (await result.rest).latencyMs
  say({
    verdict: result.verdict, reason: result.reason, raw: result.raw,
    failure: result.failure, latencyMs, streamed: Boolean(result.rest), session: result.session ?? null,
    // The parent decides and logs on this line alone, so the stage record has
    // to travel on it too.
    stage: result.stage ?? null, rule: result.rule ?? null,
    primary: result.primary ?? null, secondary: result.secondary ?? null,
    cascadeMs: result.cascadeMs ?? null,
  })
  const log = I.createLogger({ ...classifier, logDir: cfg.logDir })
  if (job.detached) {
    // Nobody is listening: this process owns the log rows the parent would
    // have written, under the parent's join keys.
    const base = job.base ?? {}
    const rec = { ...result, latencyMs, streamed: Boolean(result.rest) }
    const next = loadBreaker(cfg).record(Boolean(result.failure))
    if (result.failure && next.openedAt) {
      log.log("breaker.open", { ...base, after_consecutive_failures: next.consecutiveFailures, cooldown_ms: cooldownFor(cfg, next.opens) })
    }
    logClassification(log, I, base, job.kind, job.subject, classifier, rec, "worker-detached")
    const plan = planFor(rec, { posture: base.posture ?? cfg.posture, breakerPolicy: cfg.breakerPolicy }, job.riskyPrefix)
    const speaks = plan.outcome === "allow" || plan.outcome === "deny"
    log.log("action", { ...base, ...plan.extra, decided: speaks ? `would_${plan.outcome}` : plan.outcome, why: plan.why, detached: true })
  }
  if (result.rest) {
    const tail = await result.rest
    log.log("classification.tail", {
      ...(job.base ?? {}), permission: job.kind,
      verdict: result.verdict, reason: tail.reason, failure: tail.failure,
      latency_ms: tail.latencyMs, contradicted: tail.contradicted, raw_output: I.truncated(tail.raw, 4000),
    })
  }
  process.exit(0)
}

/**
 * Start a worker with `job` on its stdin. Resolves once the job has been
 * handed over (or the spawn failed): a parent that exits before the write
 * has left its buffer would hand the worker an empty job, so the detached
 * path awaits this before saying anything.
 */
function spawnWorker(job, { wantStdout }) {
  return new Promise((resolve) => {
    let child
    try {
      child = spawn(process.execPath, [fileURLToPath(import.meta.url), "--worker"], {
        detached: true, stdio: ["pipe", wantStdout ? "pipe" : "ignore", "ignore"], env: process.env,
      })
    } catch (e) {
      return resolve({ child: null, failure: `worker_spawn:${String(e?.message ?? e).slice(0, 200)}` })
    }
    let done = false
    const settle = (rec) => { if (!done) { done = true; resolve(rec) } }
    child.on("error", (e) => settle({ child: null, failure: `worker_spawn:${String(e?.message ?? e).slice(0, 200)}` }))
    child.unref()
    child.stdin.on("error", () => {})
    child.stdin.end(JSON.stringify(job) + "\n", () => settle({ child, failure: null }))
  })
}

/** The hook side: spawn the worker, take its first line as the classification. */
async function classifyViaWorker({ kind, subject, projectDir, base, classifier }) {
  const started = Date.now()
  const { child, failure } = await spawnWorker({ kind, subject, projectDir, base }, { wantStdout: true })
  if (!child) return { verdict: null, reason: null, raw: null, failure, latencyMs: Date.now() - started }
  return new Promise((resolve) => {
    let settled = false
    let guard = null
    const finish = (rec) => {
      if (settled) return
      settled = true
      clearTimeout(guard)
      resolve({ verdict: null, reason: null, raw: null, failure: null, ...rec, latencyMs: rec.latencyMs ?? Date.now() - started })
    }
    child.on("error", (e) => finish({ failure: `worker_spawn:${String(e?.message ?? e).slice(0, 200)}` }))
    child.on("exit", (code) => finish({ failure: `worker_exit_${code}` }))
    let buf = ""
    child.stdout.setEncoding("utf8")
    child.stdout.on("data", (chunk) => {
      buf += chunk
      const nl = buf.indexOf("\n")
      if (nl < 0) return
      let rec
      try { rec = JSON.parse(buf.slice(0, nl)) } catch { rec = { failure: "worker_bad_output" } }
      finish(rec)
    })
    child.stdout.on("end", () => finish({ failure: "worker_exited" }))
    // The worker has the classifier's own timeout; this only catches a worker
    // that never answers at all.
    guard = setTimeout(() => finish({ failure: "worker_timeout" }), classifier.timeoutMs + 1500)
  })
}

async function main() {
  // ---- fail-closed net, installed before anything can throw ----------------
  // The mode is resolved from files and env FIRST, without importing anything,
  // so a crash during import is handled according to the configured mode
  // rather than by an unconditional deny. See peekMode. An exception here is
  // a bug in this file, and in enforce a bug denies whatever the posture so
  // that it is seen and fixed. The watchdog is different, see below.
  const peek = peekMode(process.env)
  const acting = peek.mode === "enforce"
  const onFatal = acting
    ? (why) => deny(`${why} (fail-closed)`)
    : () => approve(null, `${peek.mode}: error swallowed`)
  process.on("uncaughtException", (e) => onFatal(`hook crashed: ${String(e?.message ?? e).slice(0, 300)}`))
  process.on("unhandledRejection", (e) => onFatal(`hook rejected: ${String(e?.message ?? e).slice(0, 300)}`))

  // ---- watchdog: OUR deadline, not the harness's --------------------------
  // The harness `timeout` fails open, so it must never be what fires. This
  // fires first. Running out of time is the MODEL's failure mode, not this
  // file's, so it follows the posture's FAIL column: veto and solo deny,
  // cascade says nothing. Once the logger exists, `late` is bound to decide()
  // so the outcome gets its log line; before that (stdin never arrived) it
  // can only exit.
  let late = null
  const onLate = () => {
    const outcome = POSTURES[peek.posture].FAIL
    const why = outcome === "pass"
      ? "no verdict within deadline — left to the built-in classifier"
      : "no verdict within deadline"
    if (late) return late(outcome, why, { failure: "deadline" })
    if (outcome === "deny" && acting) return deny(`${why} (fail-closed)`)
    return approve(null, why)
  }
  const watchdog = setTimeout(onLate, peek.deadlineMs)
  watchdog.unref?.()

  if (peek.mode === "off") return approve(null, "off")

  const here = path.dirname(fileURLToPath(import.meta.url))
  const modulePath = process.env.CC_CLASSIFIER_MODULE
    ?? path.resolve(here, "..", "local-classifier", "local-classifier.js")
  const { LocalClassifier } = await import(modulePath)
  const I = LocalClassifier.internals

  const { hook: cfg, classifier, problems } = resolveHookConfig(I, process.env)
  // The crash handler and the watchdog are already bound to peek's answer, so
  // peek is authoritative here. A disagreement means peekMode and
  // resolveHookConfig have drifted apart — a bug worth seeing in the log
  // rather than a condition to reconcile silently.
  if (cfg.mode !== peek.mode) {
    problems.push(`mode drift: peek=${peek.mode} resolved=${cfg.mode}; using ${peek.mode}`)
    cfg.mode = peek.mode
    classifier.mode = peek.mode
  }
  if (cfg.posture !== peek.posture) {
    problems.push(`posture drift: peek=${peek.posture} resolved=${cfg.posture}; using ${peek.posture}`)
    cfg.posture = peek.posture
  }

  const raw = await readStdin()
  let input
  try {
    input = JSON.parse(raw)
  } catch (e) {
    // Malformed stdin means we cannot know what we are being asked about.
    return acting ? deny("unreadable hook input") : approve(null, "shadow")
  }

  const tool = input?.tool_name
  const args = input?.tool_input ?? {}

  /**
   * PostToolUse: the call RAN, so if we asked about it the human said yes.
   * Collect the folder we offered and remember it. Nothing is decided here —
   * PostToolUse cannot block — so this path only ever writes state and exits 0.
   */
  if (input?.hook_event_name === "PostToolUse") {
    try {
      const root = claimAsk(cfg, input?.tool_use_id ?? null)
      if (root && acting) {
        const { added } = rememberRoot(cfg, root)
        I.createLogger({ ...classifier, logDir: cfg.logDir }).log("action", {
          harness: "claude-code", hook_version: HOOK_VERSION,
          session_id: input?.session_id ?? null, tool_use_id: input?.tool_use_id ?? null,
          tool, decided: "remembered", why: added ? `remembered ${root}` : `${root} already remembered`,
          candidateRoot: root,
        })
      }
    } catch {}
    return approve(null, "post")
  }
  const projectDir = typeof input?.cwd === "string" && input.cwd ? input.cwd : process.cwd()
  const log = I.createLogger({ ...classifier, logDir: cfg.logDir })
  const base = {
    harness: "claude-code",
    hook_version: HOOK_VERSION,
    session_id: input?.session_id ?? null,
    tool_use_id: input?.tool_use_id ?? null,
    permission_mode: input?.permission_mode ?? null,
    tool,
    posture: cfg.posture,
  }
  if (problems.length) log.log("config.problem", { ...base, problems })

  /**
   * Emit one decision and one joinable log line. `outcome` is what we say to
   * the harness: "allow" claims the call, "deny" blocks it, "pass" says
   * nothing (the built-in classifier decides), "uncovered" is pass for a tool
   * we never looked at. Shadow logs allow/deny as would_* and says nothing.
   */
  const decide = (outcome, why, extra = {}) => {
    const speaks = outcome === "allow" || outcome === "deny" || outcome === "ask"
    log.log("action", {
      ...base, ...extra,
      decided: speaks && !acting ? `would_${outcome}` : outcome,
      why,
    })
    if (outcome === "deny" && acting) return deny(why)
    if (outcome === "allow" && acting) return approve("allow", why)
    // "ask" hands the decision to the human. The candidate root is parked
    // against this tool_use_id so the PostToolUse pass knows the call it is
    // looking at is one WE asked about, and which folder was offered. In
    // shadow it logs would_ask and says nothing, like the other two.
    if (outcome === "ask" && acting) {
      if (extra.candidateRoot) parkAsk(cfg, base.tool_use_id, extra.candidateRoot)
      return askUser(why)
    }
    return approve(null, why)
  }
  late = decide

  const breaker = loadBreaker(cfg)
  const inProcess = process.env.CC_CLASSIFIER_INPROCESS === "1"
  // Detached only when nobody acts on the answer: shadow, worker path.
  const detached = !acting && cfg.shadowDetached && !inProcess

  /**
   * Run the model, record the breaker, log one joinable line. Two shortcuts
   * come first, both instant and both logged as a classification the model
   * never saw: an open breaker, and a model the flight list shows busy with a
   * long request. In detached shadow the model still runs, but in the worker
   * after this process has exited; `deferred` tells settle() to say nothing
   * and leave the log rows to the worker.
   */
  const run = async (kind, subject, riskyPrefix) => {
    if (breaker.open) {
      log.log("classification", {
        ...base, permission: kind, subject,
        skipped: "breaker_open", breaker: breaker.state,
      })
      return { verdict: null, failure: "breaker_open" }
    }
    const { busy, probe } = await probeBusy(classifier, cfg)
    if (busy) {
      log.log("classification", { ...base, permission: kind, subject, skipped: "busy", busy, probe })
      return { verdict: null, failure: "busy", busy }
    }
    if (detached) {
      const { failure } = await spawnWorker({ kind, subject, projectDir, base, detached: true, riskyPrefix }, { wantStdout: false })
      if (!failure) {
        // One parent-side row per dispatched call, so a worker that dies
        // before it can log (a broken import, an OOM kill, its own exit
        // timer) leaves a hole an analyzer can count — dispatched minus
        // classified — instead of a call that never happened.
        log.log("classification.dispatched", { ...base, permission: kind, subject, probe })
        return { verdict: null, failure: null, deferred: true }
      }
      // The worker never started, so nothing will log this call: fall through
      // to the ordinary failure path, which does.
      const result = { verdict: null, reason: null, raw: null, failure, latencyMs: 0 }
      const next = breaker.record(true)
      if (next.openedAt) {
        log.log("breaker.open", { ...base, after_consecutive_failures: next.consecutiveFailures, cooldown_ms: cooldownFor(cfg, next.opens) })
      }
      logClassification(log, I, base, kind, subject, classifier, result, "worker-detached", probe)
      return result
    }
    const result = inProcess
      ? await I.withReason(await I.classify({ kind, subject, config: classifier, projectDir }))
      : await classifyViaWorker({ kind, subject, projectDir, base, classifier })
    const next = breaker.record(Boolean(result.failure))
    if (result.failure && next.openedAt) {
      log.log("breaker.open", { ...base, after_consecutive_failures: next.consecutiveFailures, cooldown_ms: cooldownFor(cfg, next.opens) })
    }
    logClassification(log, I, base, kind, subject, classifier, result, inProcess ? "in-process" : "worker", probe)
    return result
  }

  /** Turn a classifier outcome into the decision and its log line. */
  const settle = (result, riskyPrefix) => {
    // Detached shadow: the worker writes the classification and action rows
    // under the same join keys once the model has answered. Logging an action
    // here too would count every call twice in the analyzer.
    if (result.deferred) return approve(null, "shadow: classification detached")
    const plan = planFor(result, cfg, riskyPrefix)
    return decide(plan.outcome, plan.why, plan.extra)
  }

  if (CC_BASH_TOOLS.has(tool)) {
    const command = args?.command
    if (typeof command !== "string" || !command) return decide("uncovered", "no command in tool_input")
    if (command.length > I.MAX_SUBJECT_CHARS) {
      // Not a verdict: the model never saw this input. The built-in classifier
      // has no length limit, so it decides — in every posture.
      return decide("pass", `command exceeds ${I.MAX_SUBJECT_CHARS} chars — not classified, left to the built-in classifier`,
        { skipped: "too_long" })
    }
    return settle(await run("bash", command, "classified RISKY"), "classified RISKY")
  }

  // Declared roots plus the ones approved at a prompt. Both widen the
  // boundary the same way; only their provenance differs.
  const allRoots = [...(cfg.extraRoots ?? []), ...loadRememberedRoots(cfg)]

  // Deterministic rules, no model call: predictable and instant.
  if (CC_WRITE_TOOLS.has(tool)) {
    let own = false
    for (const target of I.collectPaths(args)) {
      const abs = path.resolve(projectDir, resolveHome(target))
      const root = ccOwnRoot(abs, allRoots)
      own = own || root !== null
      const why = I.judgeWritePath(abs, root ?? projectDir)
      if (why) {
        // Is the boundary the ONLY objection? Ask the same judge again with a
        // root that would contain the target: if it passes there, nothing but
        // "outside the project" was wrong, and that is a question worth asking.
        // A sensitive path fails under any root and is never offered.
        const candidate = candidateRootFor(abs)
        const askable = cfg.outsideProjectAction === "ask" && I.judgeWritePath(abs, candidate) === null
        if (askable) {
          return decide("ask", `${tool} target ${target}: ${why}. Approving also remembers ${candidate} as an allowed folder.`,
            { candidateRoot: candidate })
        }
        return decide("deny", `${tool} target ${target}: ${why}`)
      }
    }
    return decide("pass", own
      ? "write inside Claude Code's own areas or a declared extra root"
      : "write target inside the project and not sensitive")
  }

  if (CC_READ_TOOLS.has(tool) && cfg.externalDirectory) {
    // Claude Code's own areas are read deterministically, never classified:
    // naming them in the directory prompt made the model file
    // ~/.claude/settings.json and a transcript under "the agent's designated
    // project memory area" (measured 2026-09-02). See ccOwnRoot.
    const outside = I.collectPaths(args).filter((p) => {
      const abs = path.resolve(projectDir, resolveHome(p))
      return I.isOutside(abs, projectDir) && ccOwnRoot(abs, allRoots) === null
    })
    if (outside.length === 0) return decide("pass", "read stays inside the project, Claude Code's own areas, or a declared extra root")
    const prefix = "path outside the project classified RISKY"
    return settle(await run("external_directory", outside.join("\n"), prefix), prefix)
  }

  // WebFetch, Task, MCP tools, anything added in a future release: NOT covered.
  // Logged rather than blocked — failing closed on every unknown tool id would
  // break the session outright and the hook would simply be turned off.
  return decide("uncovered", "tool not covered by this classifier")
}

/**
 * For tests only. Set CC_CLASSIFIER_LIBRARY=1 to import this file without
 * running the hook. The default is to RUN: a hook that could be imported into
 * silence by a path or argv quirk would approve every command, so the guard
 * is an explicit opt-out, never an inference from how the file was reached.
 * And the opt-out is honoured only when this file is NOT the process's entry
 * point: `node cc-classifier-hook.mjs` runs the hook whatever the environment
 * says, so the variable cannot become a kill switch that exits 0 (approve)
 * for a harness that inherited it.
 */
export const hookInternals = Object.freeze({
  HOOK_DEFAULTS, POSTURES, HOOK_VERSION,
  peekMode, resolveHookConfig, ccOwnRoot, normalizeExtraRoots,
  candidateRootFor, loadRememberedRoots, rememberRoot, parkAsk, claimAsk,
  loadBreaker, cooldownFor, probeBusy, planFor,
})

function isEntrypoint() {
  try {
    const argv1 = process.argv[1]
    return Boolean(argv1) && fs.realpathSync(argv1) === fs.realpathSync(fileURLToPath(import.meta.url))
  } catch {
    return true // an unresolvable argv[1] errs toward RUNNING the hook
  }
}

if (process.env.CC_CLASSIFIER_LIBRARY === "1" && !isEntrypoint()) {
  // imported as a library; nothing runs
} else if (process.argv.includes("--warm")) warm()
else if (process.argv.includes("--worker")) worker()
else main()
