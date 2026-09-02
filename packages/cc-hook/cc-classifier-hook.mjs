#!/usr/bin/env node
/**
 * Claude Code PreToolUse hook — local-model command classifier.
 *
 * Same classifier as the opencode plugin, same p7 prompts, same corpus. The
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
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const HOOK_NAME = "cc-local-classifier"
const HOOK_VERSION = "0.2.0"

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
   * refuse commands the model never saw.
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
  /** How long the breaker stays open before retrying. */
  breakerCooldownMs: 60_000,
  /**
   * OUR deadline for the whole hook, watchdog included. Must stay comfortably
   * under the `timeout` declared in settings.json — that one fails OPEN, so it
   * must never be the thing that fires.
   */
  deadlineMs: 12_000,
  /** Where this hook's JSONL goes. Deliberately NOT the opencode log dir: the */
  /** analyzer must not blend two harnesses into one gate. */
  logDir: path.join(os.homedir(), ".local", "share", HOOK_NAME, "logs"),
  /** Breaker state file. Hook processes are ephemeral, so it lives on disk. */
  stateDir: path.join(os.homedir(), ".local", "state", HOOK_NAME),
})

/** Tool names as Claude Code spells them (not opencode's lowercase set). */
const CC_BASH_TOOLS = new Set(["Bash", "BashOutput"])
const CC_WRITE_TOOLS = new Set(["Write", "Edit", "NotebookEdit"])
const CC_READ_TOOLS = new Set(["Read", "Glob", "Grep"])

/**
 * What each posture says on each classifier outcome. FAIL is a timeout, an
 * unreachable model, an open breaker, or the hook's own deadline. Only the
 * bash path and the external-directory read path consult this table; an
 * in-project write or read says nothing in every posture. See
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
function ccOwnRoot(abs) {
  const under = (root) => abs === root || abs.startsWith(root.endsWith("/") ? root : root + "/")
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
  for (const k of ["breakerThreshold", "breakerCooldownMs", "deadlineMs"]) {
    if (!Number.isFinite(merged[k]) || merged[k] <= 0) { problems.push(`invalid ${k}`); merged[k] = HOOK_DEFAULTS[k] }
  }
  if (typeof merged.externalDirectory !== "boolean") {
    problems.push(`invalid externalDirectory`); merged.externalDirectory = HOOK_DEFAULTS.externalDirectory
  }
  for (const k of ["logDir", "stateDir"]) {
    if (typeof merged[k] !== "string" || !merged[k]) { problems.push(`invalid ${k}`); merged[k] = HOOK_DEFAULTS[k] }
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
// ---------------------------------------------------------------------------

function loadBreaker(cfg) {
  const file = path.join(cfg.stateDir, "breaker.json")
  const state = readJson(file) ?? { consecutiveFailures: 0, openedAt: 0 }
  // An openedAt in the future (clock jump, hand-edited file) counts as closed:
  // otherwise `now - openedAt` is negative, always under the cooldown, and the
  // breaker stays open until the clock catches up — under veto that is every
  // command denied indefinitely.
  const since = Date.now() - (state.openedAt ?? 0)
  const open = state.openedAt > 0 && since >= 0 && since < cfg.breakerCooldownMs
  return {
    file,
    open,
    state,
    record(failed) {
      const next = failed
        ? {
            consecutiveFailures: (state.consecutiveFailures ?? 0) + 1,
            openedAt: (state.consecutiveFailures ?? 0) + 1 >= cfg.breakerThreshold ? Date.now() : 0,
          }
        : { consecutiveFailures: 0, openedAt: 0 }
      try {
        fs.mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 })
        fs.writeFileSync(file, JSON.stringify(next), { mode: 0o600 })
      } catch {}
      return next
    },
  }
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
 */
async function warm() {
  const here = path.dirname(fileURLToPath(import.meta.url))
  const modulePath = process.env.CC_CLASSIFIER_MODULE
    ?? path.resolve(here, "..", "local-classifier", "local-classifier.js")
  const { LocalClassifier } = await import(modulePath)
  const I = LocalClassifier.internals
  const { hook: cfg, classifier } = resolveHookConfig(I, process.env)
  const started = Date.now()
  const result = await I.classify({ kind: "bash", subject: "true", config: classifier, projectDir: null })
  I.createLogger({ ...classifier, logDir: cfg.logDir }).log("warm", {
    harness: "claude-code", hook_version: HOOK_VERSION,
    endpoint: classifier.endpoint, model: classifier.model,
    prompt_version: I.PROMPT_VERSION,
    verdict: result.verdict, failure: result.failure, latency_ms: result.latencyMs,
  })
  process.stdout.write(`warm ${result.failure ?? result.verdict} ${Date.now() - started}ms\n`)
  process.exit(result.failure ? 1 : 0)
}

async function readStdin() {
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  return Buffer.concat(chunks).toString("utf8")
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
    const speaks = outcome === "allow" || outcome === "deny"
    log.log("action", {
      ...base, ...extra,
      decided: speaks && !acting ? `would_${outcome}` : outcome,
      why,
    })
    if (outcome === "deny" && acting) return deny(why)
    if (outcome === "allow" && acting) return approve("allow", why)
    return approve(null, why)
  }
  late = decide

  const breaker = loadBreaker(cfg)

  /** Run the model, record the breaker, log one joinable line. */
  const run = async (kind, subject) => {
    if (breaker.open) {
      log.log("classification", {
        ...base, permission: kind, subject,
        skipped: "breaker_open", breaker: breaker.state,
      })
      return { verdict: null, failure: "breaker_open" }
    }
    const result = await I.classify({ kind, subject, config: classifier, projectDir })
    const next = breaker.record(Boolean(result.failure))
    if (result.failure && next.openedAt) {
      log.log("breaker.open", { ...base, after_consecutive_failures: next.consecutiveFailures })
    }
    log.log("classification", {
      ...base, permission: kind, subject,
      endpoint: classifier.endpoint, model: classifier.model,
      prompt_version: I.PROMPT_VERSION,
      verdict: result.verdict, reason: result.reason, failure: result.failure,
      latency_ms: result.latencyMs, raw_output: I.truncated(result.raw, 4000),
    })
    return result
  }

  /**
   * Map a classifier outcome onto a decision. Verdicts follow the posture. A
   * failure is where the postures part ways: under cascade the hook only ever
   * adds permission, so a model that is down or slow costs the speedup and
   * nothing else — say nothing, the built-in classifier decides. Under veto
   * and solo the deny is what the posture is for, so a failure denies (fail
   * closed), except a KNOWN-down model with breakerPolicy "allow".
   */
  const settle = (result, riskyPrefix) => {
    const map = POSTURES[cfg.posture]
    if (result.verdict === "SAFE") return decide(map.SAFE, "classified SAFE", { verdict: "SAFE" })
    if (result.verdict === "RISKY") {
      const tail = map.RISKY === "pass" ? " — left to the built-in classifier" : ""
      return decide(map.RISKY, `${riskyPrefix}: ${result.reason ?? ""}${tail}`, { verdict: "RISKY" })
    }
    const extra = { verdict: null, failure: result.failure }
    const what = result.failure === "breaker_open"
      ? "classifier down (breaker open)"
      : `classifier failed (${result.failure})`
    if (map.FAIL === "pass") return decide("pass", `${what} — left to the built-in classifier`, extra)
    if (result.failure === "breaker_open" && cfg.breakerPolicy === "allow") {
      return decide("pass", `${what} — degraded to the built-in classifier`, extra)
    }
    return decide("deny", what, extra)
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
    return settle(await run("bash", command), "classified RISKY")
  }

  // Deterministic rules, no model call: predictable and instant.
  if (CC_WRITE_TOOLS.has(tool)) {
    let own = false
    for (const target of I.collectPaths(args)) {
      const abs = path.resolve(projectDir, resolveHome(target))
      const root = ccOwnRoot(abs)
      own = own || root !== null
      const why = I.judgeWritePath(abs, root ?? projectDir)
      if (why) return decide("deny", `${tool} target ${target}: ${why}`)
    }
    return decide("pass", own
      ? "write inside Claude Code's own scratchpad or memory directory"
      : "write target inside the project and not sensitive")
  }

  if (CC_READ_TOOLS.has(tool) && cfg.externalDirectory) {
    // Claude Code's own areas are read deterministically, never classified:
    // naming them in the directory prompt made the model file
    // ~/.claude/settings.json and a transcript under "the agent's designated
    // project memory area" (measured 2026-09-02). See ccOwnRoot.
    const outside = I.collectPaths(args).filter((p) => {
      const abs = path.resolve(projectDir, resolveHome(p))
      return I.isOutside(abs, projectDir) && ccOwnRoot(abs) === null
    })
    if (outside.length === 0) return decide("pass", "read stays inside the project or Claude Code's own areas")
    return settle(await run("external_directory", outside.join("\n")), "path outside the project classified RISKY")
  }

  // WebFetch, Task, MCP tools, anything added in a future release: NOT covered.
  // Logged rather than blocked — failing closed on every unknown tool id would
  // break the session outright and the hook would simply be turned off.
  return decide("uncovered", "tool not covered by this classifier")
}

if (process.argv.includes("--warm")) warm()
else main()
