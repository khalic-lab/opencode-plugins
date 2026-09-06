/**
 * omp local-classifier — a local safety classifier in front of Oh My Pi's tool
 * calls, sharing one prompt and one decision core with the opencode plugin.
 *
 * WHY THIS IS SHAPED DIFFERENTLY FROM THE OPENCODE PLUGIN
 *
 * opencode asks the human and lets a plugin answer the prompt, so the plugin's
 * job there is to auto-APPROVE and its fallback is "leave the prompt up". omp
 * resolves approval synchronously inside its tool wrapper from tier + policy +
 * mode, and its `tool_approval_requested` / `tool_approval_resolved` events are
 * pure `emit` whose return value is discarded (wrapper.ts:281-300 at 18.1.5).
 * Nothing an extension can register answers an omp prompt. What an extension
 * CAN do is `tool_call`, which fires before the approval gate and which omp
 * awaits — so here the classifier is a VETO over `approvalMode: yolo`, not an
 * approver, and its fallback is to block or to ask.
 *
 * That inversion deletes most of the opencode plugin's hazards rather than
 * porting them. There is no pending map, no countdown for the human to beat,
 * no reply race, no "once" vs "always" choice, and no reply-intent ordering:
 * the decision is in-band and omp blocks on our promise. Two of the opencode
 * fail-closed invariants are now enforced by the runtime instead of by us —
 * `emitToolCall` converts BOTH a handler throw and a handler timeout into
 * `{block: true}` (runner.ts:1470-1508), so a crash or a hang in this file
 * cannot become silent consent.
 *
 * WHAT CARRIES OVER UNCHANGED
 *
 * The bash subject. opencode sends `metadata.command`, the exact string handed
 * to the shell; omp's `tool_call` event carries `input.command`, verified by
 * probe on 2026-09-03 at omp 18.1.5 to be exactly `{"command":"echo probe-ok"}`
 * for `echo probe-ok`. Same bytes, so PROMPT_VERSION and the existing shadow
 * corpus stay valid for bash and the two hosts' verdicts may be pooled. A test
 * asserts this rather than trusting it, because `normalizeToolEventInput` sits
 * in the path and could start reshaping the view.
 *
 * WHAT DOES NOT CARRY OVER
 *
 * The directory half. opencode has an `external_directory` permission that
 * hands over a glob plus a filepath; omp has no analogue — write/edit are tier
 * `write` and simply auto-approve under yolo. Judging their inputs is a NEW
 * subject shape and would need its own prompt version and its own shadow run,
 * so v1 classifies bash only and `tools.write`/`tools.edit` default to false.
 * The deterministic path judging (judgeWritePath) is still applied to those
 * tools when they are switched on, because that half needs no model.
 *
 * MODES
 *
 * off      — nothing is classified.
 * shadow   — classify, log, NEVER act. See the note on labels below.
 * enforce  — SAFE allows; RISKY or any failure takes `riskyAction`.
 *
 * SHADOW MEANS SOMETHING DIFFERENT HERE, AND IT MATTERS
 *
 * In opencode, shadow captured the HUMAN's decision from `permission.replied`
 * and filed it next to our verdict, which is what made the logs a labeled eval
 * set. Under omp's default `approvalMode: yolo` there is no human decision to
 * capture — shadow would log verdicts against no ground truth. So this file
 * also subscribes to `tool_approval_resolved`, which fires only when a call
 * actually required approval. Run shadow with `tools.approvalMode: write` (or
 * `always-ask`) and exec-tier calls still prompt: our verdict and the human's
 * answer both reach the log, keyed by toolCallId, and the eval set is labeled
 * exactly as it was in opencode. Run shadow under yolo and you get verdicts
 * only, which you must hand-label. `/classifier status` reports which of the
 * two you are actually in, because getting this wrong silently produces an
 * unlabeled corpus that looks fine.
 *
 * THE 30-SECOND CAP
 *
 * Every `tool_call` handler is bounded by `extensionHandlers.toolCallTimeoutMs`
 * (default 30000). Classification fits easily. A confirm dialog waiting on a
 * human does not, and blowing the cap surfaces as a block with an "extension
 * timed out" reason rather than a prompt. So `riskyAction: "confirm"` requires
 * raising that setting — `normalizeHandlerTimeout` accepts any finite positive
 * value, so a large one is legal. The default here is "block" precisely so the
 * confirm path is opt-in after you have raised the cap.
 *
 * Zero dependencies beyond the shared core. Extensions run in-process with no
 * isolation: every handler body is wrapped, and background work uses
 * ctx.setInterval, because a throw from a raw timer tears the session down.
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"

import { LocalClassifier } from "opencode-local-classifier"

/**
 * The transport-agnostic core, reached through the `.internals` surface the
 * opencode plugin already exposes for its own tests and eval tooling. Importing
 * it rather than copying it is the whole point: cc-hook is 983 lines that share
 * nothing with local-classifier.js, and a third independent copy would mean
 * three places to bump PROMPT_VERSION — which the plugin's own header forbids
 * blending. Nothing here calls the plugin factory, so no opencode code runs.
 */
const I = LocalClassifier.internals

const EXTENSION_NAME = "omp-local-classifier"
const EXTENSION_VERSION = "0.1.0"

/** Tools we can classify with the bash prompt, i.e. whose subject is a command string. */
const BASH_TOOLS = new Set(["bash"])
/** Tools judged deterministically by path, never sent to the model in v1. */
const PATH_TOOLS = new Set(["write", "edit", "apply_patch", "patch", "multiedit"])

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const OMP_USER_FILE = path.join(os.homedir(), ".omp", "agent", "extensions", EXTENSION_NAME, "config.json")
const OMP_PROJECT_FILE = path.join(".omp", "local-classifier.json")
/**
 * Folders approved at a prompt. Kept apart from config.json on purpose:
 * extraRoots is what you declared by hand, this is what you agreed to when
 * asked. Two files means you can read back what the extension granted itself,
 * and delete this one without losing your settings.
 */
const OMP_REMEMBERED_FILE = path.join(os.homedir(), ".omp", "agent", "extensions", EXTENSION_NAME, "remembered-roots.json")

/** Extra keys this host adds on top of the shared DEFAULTS. */
const OMP_DEFAULTS = Object.freeze({
  /** "block" | "confirm" — what a RISKY verdict or a failure does in enforce. */
  riskyAction: "block",
  /**
   * Apply the DETERMINISTIC path rules (judgeWritePath — sensitive paths and
   * outside-the-project writes) to write/edit tools. No model is involved.
   *
   * Deliberately not "also classify those tools with the model":
   * DIRECTORY_SYSTEM_PROMPT was written for opencode's two-line subject, the
   * exact target file AND the `dirname + "/*"` glob the approval would grant,
   * and it tells the model the list "may contain … a directory pattern ending
   * in /*". omp has no external_directory permission and so no glob to send.
   * Feeding it a bare path would be off-distribution for a prompt that
   * describes something not present, which is a silent accuracy loss rather
   * than an error. That half needs its own prompt version and its own shadow
   * run before any model sees it.
   */
  pathRules: false,
  /**
   * Extra directories to treat as project roots. A target under one of these
   * is judged with that root as its project, so the "outside the project
   * directory" rule stops firing there — and nothing else changes, because
   * judgeWritePath still applies SENSITIVE_PATH_PATTERNS first. Declaring a
   * root cannot unlock an ~/.ssh or a shell profile inside it.
   *
   * A session's project is wherever it was started, and real work spans trees.
   * Trusted (user-file) layer only; the untrusted project layer may not set it,
   * or a cloned repo could widen its own boundary.
   */
  extraRoots: [],
  /**
   * What a write does when its ONLY objection is that it lands outside the
   * session's project directory.
   *   "deny" — refuse it.
   *   "ask"  — put it to the human, and remember the folder if they approve.
   * A sensitive path is never askable and always denies, declared root or not.
   *
   * Asking costs the handler budget: this branch runs no model, so the whole
   * `extensionHandlers.toolCallTimeoutMs` (default 30000) is available for the
   * dialog — but 30 s is short for a human, and overrunning it surfaces as a
   * block with an "extension timed out" reason. Raise that setting before
   * relying on "ask".
   */
  outsideProjectAction: "deny",
})

/**
 * Validate user-declared roots. A root that aliases HOME, `/`, or a system
 * directory would switch the boundary rule off for most of the disk, so those
 * are rejected outright rather than clamped — a silently narrowed root looks
 * like it worked. Relative paths are rejected because cwd is the session's,
 * not the config file's.
 */
function normalizeExtraRoots(value, problems) {
  if (value === undefined) return []
  if (!Array.isArray(value)) {
    problems.push("invalid extraRoots (not an array)")
    return []
  }
  const home = os.homedir()
  const forbidden = new Set(["/", home, "/etc", "/usr", "/var", "/System", "/Library", "/bin", "/sbin", "/opt"])
  const out = []
  for (const entry of value) {
    if (typeof entry !== "string" || !entry.trim()) {
      problems.push(`invalid extraRoots entry ${JSON.stringify(entry)}`)
      continue
    }
    const raw = entry.trim()
    const abs = path.resolve(raw.startsWith("~") ? path.join(home, raw.slice(1)) : raw)
    if (forbidden.has(abs)) {
      problems.push(`extraRoots entry ${raw} resolves to ${abs}, which is too broad; ignored`)
      continue
    }
    if (home === abs || home.startsWith(abs.endsWith("/") ? abs : abs + "/")) {
      problems.push(`extraRoots entry ${raw} contains the home directory; ignored`)
      continue
    }
    out.push(abs)
  }
  return out
}


/**
 * The folder we would offer to remember for `abs`: the nearest ancestor holding
 * a .git, else the file's own directory. Offering a repo rather than a single
 * directory is what makes this once-per-project instead of once-per-file, and a
 * repo root is a boundary the user already drew.
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

/** Folders approved at a prompt. Re-validated on read: the file is ours, but an over-broad entry must never take effect. */
function loadRememberedRoots(file = OMP_REMEMBERED_FILE) {
  const data = readJson(file)
  return normalizeExtraRoots(Array.isArray(data?.roots) ? data.roots : [], [])
}

/** Record one approved folder. Idempotent; a failed write is reported, never thrown. */
function rememberRoot(root, file = OMP_REMEMBERED_FILE) {
  const current = loadRememberedRoots(file)
  if (current.includes(root)) return { added: false, roots: current }
  const roots = [...current, root]
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  fs.writeFileSync(file, JSON.stringify({ roots }, null, 2) + "\n", { mode: 0o600 })
  return { added: true, roots }
}

/** The declared root containing `abs`, or null. */
function rootFor(abs, extraRoots) {
  for (const root of extraRoots) {
    if (abs === root || abs.startsWith(root.endsWith("/") ? root : root + "/")) return root
  }
  return null
}

function readJson(file) {
  let text
  try {
    text = fs.readFileSync(file, "utf8")
  } catch {
    return null
  }
  try {
    return JSON.parse(text)
  } catch (e) {
    return { __parseError: String(e?.message ?? e).slice(0, 200) }
  }
}

/**
 * Reuse the shared resolver verbatim — including its trust rules, its
 * per-field validation and its "a cloned repo may not raise the mode" logic —
 * by translating the two paths it asks for onto omp's equivalents. The layer
 * ORDER is what decides trust in that resolver, and the shim preserves it:
 * layer 0 stays the user file (trusted), layer 1 stays the project file
 * (untrusted, may only lower the mode and set the few allowed keys).
 */
function resolveOmpConfig({ worktree, env = process.env } = {}) {
  const readFile = (file) => {
    if (file.endsWith(path.join(".config", "opencode", "local-classifier.json"))) return readJson(OMP_USER_FILE)
    if (file.endsWith(path.join(".opencode", "local-classifier.json"))) {
      return worktree ? readJson(path.join(worktree, OMP_PROJECT_FILE)) : null
    }
    return null
  }
  // The shared resolver reads OPENCODE_-prefixed env; accept the OMP_ spelling
  // as an alias so one host's variable cannot silently configure the other.
  const shimmedEnv = { ...env }
  if (typeof env.OMP_LOCAL_CLASSIFIER_MODE === "string") {
    shimmedEnv.OPENCODE_LOCAL_CLASSIFIER_MODE = env.OMP_LOCAL_CLASSIFIER_MODE
  }
  if (env.OMP_LOCAL_CLASSIFIER_TRUST_OPTIONS === "1") shimmedEnv.OPENCODE_LOCAL_CLASSIFIER_TRUST_OPTIONS = "1"

  const resolved = I.resolveConfig({ options: undefined, worktree, env: shimmedEnv, readFile })

  // Host-specific keys are validated here, since the shared resolver rejects
  // anything not in its own DEFAULTS.
  const user = readJson(OMP_USER_FILE)
  const out = { ...OMP_DEFAULTS, ...resolved.config }
  const problems = [...resolved.problems]
  if (user && typeof user === "object" && !user.__parseError) {
    if (user.riskyAction !== undefined) {
      if (user.riskyAction === "block" || user.riskyAction === "confirm") out.riskyAction = user.riskyAction
      else problems.push(`invalid riskyAction ${JSON.stringify(user.riskyAction)}`)
    }
    if (user.pathRules !== undefined) {
      if (typeof user.pathRules === "boolean") out.pathRules = user.pathRules
      else problems.push("invalid pathRules")
    }
    out.extraRoots = normalizeExtraRoots(user.extraRoots, problems)
    if (user.outsideProjectAction !== undefined) {
      if (user.outsideProjectAction === "deny" || user.outsideProjectAction === "ask") {
        out.outsideProjectAction = user.outsideProjectAction
      } else problems.push(`invalid outsideProjectAction ${JSON.stringify(user.outsideProjectAction)}`)
    }
  }
  // Declared roots plus the ones approved at a prompt. Both widen the boundary
  // the same way; only their provenance differs.
  out.extraRoots = [...(out.extraRoots ?? []), ...loadRememberedRoots()]
  return { ...resolved, config: out, problems }
}

// ---------------------------------------------------------------------------
// Subject extraction
// ---------------------------------------------------------------------------

/**
 * The text the classifier judges, or null when this call is not ours to judge.
 *
 * bash only, on purpose — see OMP_DEFAULTS.pathRules for why write/edit inputs
 * never reach the model in v1.
 *
 * For bash the subject is `input.command` and nothing else. There is
 * deliberately no fallback to a reconstructed command: opencode's plugin
 * learned that joining AST fragments describes a DIFFERENT command than the
 * one that runs, and the same reasoning applies to any guess we might make
 * from a partial event.
 */
function subjectFor(toolName, input) {
  if (!BASH_TOOLS.has(toolName)) return null
  const command = input?.command
  if (typeof command !== "string" || !command.trim()) return null
  return { kind: "bash", subject: I.sanitizeSubject(command) }
}

// ---------------------------------------------------------------------------
// Extension
// ---------------------------------------------------------------------------

export default function ompLocalClassifier(pi) {
  // Registration phase only — runtime actions are not wired yet, and calling
  // one here throws ExtensionRuntimeNotInitializedError.
  let config = null
  let log = null
  let breaker = null
  let warmTimer = null
  const counters = { checked: 0, safe: 0, risky: 0, failed: 0, blocked: 0, asked: 0, labeled: 0 }
  /** toolCallId -> our verdict, so `tool_approval_resolved` can label it. */
  const pending = new Map()
  const PENDING_MAX = 500

  /**
   * Every line is stamped `host: "omp"`. The shared logger stamps `plugin` and
   * `v` from the opencode package's own constants, and both hosts write to the
   * same logDir by default — which is what makes one pooled bash corpus
   * possible, and exactly why each line has to say where it came from. Without
   * this the analyzer cannot separate the hosts, and a difference in verdict
   * distribution between them would be invisible.
   */
  const safeLog = (event, fields) => {
    try {
      return log ? log.log(event, { host: "omp", ...fields }) : false
    } catch {
      return false
    }
  }

  pi.on("session_start", async (_event, ctx) => {
    try {
      const resolved = resolveOmpConfig({ worktree: ctx?.cwd })
      config = resolved.config
      log = I.createLogger(config)
      breaker = I.createBreaker({ threshold: config.breakerThreshold, cooldownMs: config.breakerCooldownMs })

      safeLog("init", {
        extension: EXTENSION_NAME,
        extensionVersion: EXTENSION_VERSION,
        promptVersion: I.PROMPT_VERSION,
        host: "omp",
        mode: config.mode,
        modeSource: resolved.modeSource,
        sources: resolved.sources,
        problems: resolved.problems,
        riskyAction: config.riskyAction,
        pathRules: config.pathRules,
        extraRoots: config.extraRoots,
        endpoint: config.endpoint,
        model: config.model,
        cwd: ctx?.cwd ?? null,
        hasUI: ctx?.hasUI ?? false,
      })

      // Keep the local server's prefix cache warm. ctx.setInterval, never a raw
      // timer: a throw from a detached callback is an uncaughtException and the
      // postmortem handler treats it as fatal to the whole session.
      if (config.mode !== "off" && config.warmIntervalMs > 0) {
        warmTimer = ctx.setInterval(() => {
          void I.classify({
            kind: "bash",
            subject: "true",
            config: { ...config, timeoutMs: Math.min(config.timeoutMs, 5_000) },
            projectDir: ctx?.cwd ?? null,
          }).catch(() => {})
        }, config.warmIntervalMs)
      }
    } catch (e) {
      // A broken init must not take the session with it; it leaves config null,
      // and the tool_call handler treats that as "not configured" and stands
      // aside rather than blocking every call in the session.
      try {
        console.error(`[${EXTENSION_NAME}] init failed: ${e?.message ?? e}`)
      } catch {}
    }
  })

  pi.on("session_shutdown", (_event, ctx) => {
    try {
      if (warmTimer) ctx.clearTimer(warmTimer)
    } catch {}
  })

  /**
   * Label capture. These events fire only when a call actually required
   * approval AND a handler is registered — subscribing is what turns them on.
   * Under `approvalMode: write` in shadow, this is where the human's answer
   * meets our verdict and the corpus becomes a labeled eval set.
   */
  pi.on("tool_approval_resolved", async (event) => {
    try {
      const ours = pending.get(event?.toolCallId)
      if (!ours) return
      pending.delete(event.toolCallId)
      counters.labeled += 1
      safeLog("human_decision", {
        toolCallId: event.toolCallId,
        toolName: event.toolName,
        verdict: ours.verdict,
        failure: ours.failure,
        approved: event.approved === true,
        agreed: ours.verdict ? (ours.verdict === "SAFE") === (event.approved === true) : null,
      })
    } catch {}
  })

  pi.on("tool_call", async (event, ctx) => {
    // Everything below is wrapped. A throw here would block the call, which is
    // the safe direction, but an unexplained block is a bad experience — so we
    // catch, log, and fall back to the configured posture explicitly.
    try {
      if (!config || config.mode === "off") return undefined

      const toolName = event?.toolName

      /**
       * Deterministic path rules, no model. They hold even when the breaker is
       * open or the classifier is down, which is why they run before it.
       *
       * The audit line here is best-effort, unlike the SAFE path below. The
       * opencode invariant is "no APPROVAL without a durable audit line" —
       * blocking with no line loses a record but never grants anything, so a
       * failed write must not be allowed to turn a block into an allow.
       */
      if (PATH_TOOLS.has(toolName)) {
        if (!config.pathRules) return undefined
        return decidePath(ctx, config, toolName, event?.input, counters, safeLog)
      }

      const found = subjectFor(toolName, event?.input)
      if (!found) return undefined

      if (breaker?.isOpen()) {
        counters.checked += 1
        counters.failed += 1
        safeLog("breaker_open", { toolName, state: breaker.state() })
        return decide(ctx, config, "classifier circuit breaker is open", counters, safeLog)
      }

      const gen = breaker?.generation()
      const result = await I.withReason(
        await I.classify({
          kind: found.kind,
          subject: found.subject,
          config,
          projectDir: ctx?.cwd ?? null,
        }),
      )

      counters.checked += 1
      if (result.failure) {
        counters.failed += 1
        breaker?.recordFailure(gen)
      } else {
        breaker?.recordSuccess(gen)
        if (result.verdict === "SAFE") counters.safe += 1
        else counters.risky += 1
      }

      const wrote = safeLog("classification", {
        toolCallId: event?.toolCallId,
        toolName,
        kind: found.kind,
        subject: I.truncated(found.subject, I.MAX_SUBJECT_CHARS),
        promptVersion: I.PROMPT_VERSION,
        verdict: result.verdict,
        reason: result.reason ? I.truncated(result.reason, 300) : null,
        failure: result.failure,
        latencyMs: result.latencyMs,
        fullLatencyMs: result.fullLatencyMs ?? null,
        contradicted: result.contradicted ?? null,
      })

      if (pending.size < PENDING_MAX && event?.toolCallId) {
        pending.set(event.toolCallId, { verdict: result.verdict, failure: result.failure })
      }

      if (config.mode === "shadow") return undefined

      if (result.verdict === "SAFE" && !result.failure) {
        // No approval without a durable audit line — the opencode plugin's
        // invariant 4b, and the one that does still apply here.
        if (!wrote) {
          safeLog("audit_gap", { toolCallId: event?.toolCallId, toolName })
          return decide(ctx, config, "classification could not be written to the audit log", counters, safeLog)
        }
        return undefined
      }

      const why = result.failure
        ? `classifier ${result.failure}`
        : `classified RISKY${result.reason ? `: ${I.truncated(result.reason, 200)}` : ""}`
      return decide(ctx, config, why, counters, safeLog)
    } catch (e) {
      safeLog("handler_error", { error: String(e?.message ?? e).slice(0, 300) })
      return { block: true, reason: `${EXTENSION_NAME}: handler error, failing closed` }
    }
  })

  pi.registerCommand("classifier", {
    description: "local-classifier status",
    handler: async (_args, ctx) => {
      /**
       * Whether shadow is producing a LABELED corpus is reported from what has
       * actually been observed, not from config. `tools.approvalMode` is not
       * reachable: ExtensionContext exposes ui/hasUI/cwd/sessionManager/
       * modelRegistry/models/timers and friends, but no `settings` (runner.ts
       * createContext, 18.1.5). Reading it optionally would have silently
       * reported "unlabeled" even when the mode was set correctly — worse than
       * no line, since that is the exact misconfiguration this is here to
       * catch. A human answer arriving through tool_approval_resolved is
       * direct evidence that approval is being requested at all.
       */
      const lines = config
        ? [
            `mode=${config.mode} riskyAction=${config.riskyAction} promptVersion=${I.PROMPT_VERSION}`,
            `model=${config.model}`,
            `checked=${counters.checked} safe=${counters.safe} risky=${counters.risky} failed=${counters.failed} blocked=${counters.blocked} asked=${counters.asked}`,
            config.mode === "shadow"
              ? counters.labeled > 0
                ? `shadow is LABELED: ${counters.labeled}/${counters.checked} verdicts have a human answer beside them`
                : `shadow is UNLABELED so far: no approval prompts seen. Under approvalMode=yolo there is nothing to label against — set tools.approvalMode: write to capture human answers.`
              : null,
            `log=${config.logDir}`,
          ].filter(Boolean)
        : ["not initialized"]
      ctx.ui.notify(lines.join("\n"), "info")
    },
  })
}

/**
 * Test surface. Unlike opencode — whose loader calls every export as a plugin
 * factory and rejects the module when one is not a function — omp loads the
 * default export only, so named exports are safe here.
 */
export const internals = {
  EXTENSION_NAME,
  EXTENSION_VERSION,
  OMP_DEFAULTS,
  OMP_USER_FILE,
  OMP_PROJECT_FILE,
  BASH_TOOLS,
  PATH_TOOLS,
  subjectFor,
  resolveOmpConfig,
  normalizeExtraRoots,
  rootFor,
  candidateRootFor,
  loadRememberedRoots,
  rememberRoot,
  decidePath,
  decide,
}

/**
 * The write/edit path rules, and the one place a folder can be approved.
 *
 * Two objections can come back from judgeWritePath, and they are not treated
 * alike. A sensitive target — credentials, SSH keys, shell or system config,
 * this extension's own code — is never negotiable and never reaches a prompt,
 * inside a remembered folder or not. A target whose *only* problem is that it
 * sits outside the session's project is a boundary question, and a boundary is
 * something the human is entitled to move. Under `outsideProjectAction: "ask"`
 * that one is put to them, and approving it remembers the enclosing repository
 * so the next write there is silent.
 *
 * The folder we offer must be a folder we can store: candidateRootFor falls
 * back to the file's own directory, which can be anywhere, so it goes through
 * the same normalizeExtraRoots that guards the config file. Offering a root
 * that the loader would later drop would ask the same question forever.
 *
 * `remember` is a parameter so tests can watch what would be written without
 * touching the real state file.
 */
async function decidePath(ctx, config, toolName, input, counters, safeLog, remember = rememberRoot) {
  for (const p of I.collectPaths(input ?? {})) {
    // A declared root replaces cwd as the boundary for targets inside it.
    // judgeWritePath still applies the sensitive-path patterns first, so a
    // root cannot unlock credentials or shell config within itself.
    const roots = config.extraRoots ?? []
    const abs = path.resolve(ctx?.cwd ?? process.cwd(), p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p)
    const root = rootFor(abs, roots)
    const reason = I.judgeWritePath(abs, root ?? ctx?.cwd ?? null)
    if (!reason) continue

    counters.checked += 1
    counters.risky += 1

    const candidate = candidateRootFor(abs)
    const storable = normalizeExtraRoots([candidate], []).length === 1
    const boundaryOnly = storable && I.judgeWritePath(abs, candidate) === null
    const askable =
      boundaryOnly && config.mode === "enforce" && config.outsideProjectAction === "ask" && ctx?.hasUI === true

    safeLog("path_deny", { toolName, path: I.truncated(p, 300), reason, boundaryOnly, candidateRoot: candidate })
    if (!askable) return decide(ctx, config, `${toolName}: ${reason}`, counters, safeLog)

    const why = `${toolName}: ${reason}`
    let ok = false
    try {
      counters.asked += 1
      ok = await ctx.ui.confirm("local-classifier", `${why}\n\nAllow it, and remember ${candidate} from now on?`)
    } catch (e) {
      safeLog("confirm_error", { error: String(e?.message ?? e).slice(0, 200) })
      return blockNow(counters, safeLog, `${EXTENSION_NAME}: ${why} (confirm unavailable)`)
    }
    if (ok !== true) return blockNow(counters, safeLog, `${EXTENSION_NAME}: ${why} (declined)`)

    // The human said yes, so the write proceeds even if we cannot persist the
    // folder — a failed write costs them the same prompt again next session,
    // and turning their approval into a block would be the worse answer.
    let added = false
    try {
      added = remember(candidate)?.added === true
    } catch (e) {
      safeLog("remember_error", { candidateRoot: candidate, error: String(e?.message ?? e).slice(0, 200) })
    }
    // Reassigned, not pushed: the array may be OMP_DEFAULTS.extraRoots, which
    // is frozen, and a throw here would turn an approval into a block.
    config.extraRoots = roots.includes(candidate) ? roots : [...roots, candidate]
    safeLog("root_approved", { candidateRoot: candidate, persisted: added })
  }
  return undefined
}

/**
 * The one shape a refusal takes. Every path that must not proceed returns
 * through here, so the counter, the audit line and the reason string cannot
 * drift apart between the two decision functions.
 */
function blockNow(counters, safeLog, reason) {
  counters.blocked += 1
  safeLog("action.block", { reason: reason.slice(0, 300) })
  return { block: true, reason }
}

/**
 * What a RISKY verdict or a failure actually does. Kept in one place so every
 * path that must not proceed goes through the same posture, and so the headless
 * case cannot accidentally become an allow.
 */
async function decide(ctx, config, why, counters, safeLog) {
  if (config.mode !== "enforce") return undefined

  const block = (reason) => blockNow(counters, safeLog, reason)

  if (config.riskyAction !== "confirm" || !ctx?.hasUI) {
    // Headless (subagents, print mode) has no one to ask. Probed at 18.1.5:
    // ctx.ui.confirm with no UI resolves false in 0ms, so even the confirm
    // posture degrades to a block here rather than to an allow.
    return block(`${EXTENSION_NAME}: ${why}`)
  }

  try {
    counters.asked += 1
    const ok = await ctx.ui.confirm("local-classifier", `${why}\n\nRun it anyway?`)
    if (ok === true) {
      safeLog("action.human_override", { why: why.slice(0, 300) })
      return undefined
    }
    return block(`${EXTENSION_NAME}: ${why} (declined)`)
  } catch (e) {
    safeLog("confirm_error", { error: String(e?.message ?? e).slice(0, 200) })
    return block(`${EXTENSION_NAME}: ${why} (confirm unavailable)`)
  }
}
