#!/usr/bin/env node
/**
 * Watches the remote model box FROM THIS MAC.
 *
 * It lives here rather than on the box on purpose: a watchdog that runs on the
 * machine it watches can only restart a process, and it goes silent in exactly
 * the case that matters most — the box being off, asleep, or off the network.
 * Running it here means "the remote is unreachable" is itself an observation
 * this machine can report, and the classifier's own host is the one that learns
 * the primary is gone.
 *
 * WHY IT PROBES WITH A COMPLETION AND NOT /v1/models
 * Measured 2026-09-06: `GET /v1/models` answered HTTP 200 in 52 ms while every
 * `POST /v1/chat/completions` hung past 120 s with no response at all. The HTTP
 * layer outlives the inference loop, so a liveness check on the model list is
 * not just weak, it reports "up" during the precise failure this exists to
 * catch. The probe therefore asks for a real token, and the two checks together
 * are what separate the three states:
 *
 *   up      a completion came back inside the budget
 *   wedged  the model list answers but a completion does not  <- the 09-06 case
 *   down    nothing answers
 *
 * WHY THE PROBE IS A REAL CLASSIFICATION
 * There are two different cold starts and a keepalive has to beat both. The
 * model being evicted from GPU memory costs 17 s on that box; the classifier's
 * ~3.2k-token system prompt being evicted from the server's prompt cache costs
 * a full prefill instead of the ~15 tokens a warm call prefills, which is where
 * every latency outlier in the shadow corpus came from. A throwaway "reply OK"
 * fixes only the first: it shares no prefix with a real classification, so it
 * warms nothing the classifier will hit, and on a small `--prompt-cache-size` it
 * can evict the entry that mattered. So the probe sends the classifier's own
 * system prompt, through the classifier's own code, in the shape the cascade's
 * PRIMARY uses — whole answer, logprobs on. That also makes it the request that
 * hung on 2026-09-06, which a lighter probe would have missed.
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { execFile } from "node:child_process"
import { fileURLToPath } from "node:url"

// Importing the classifier is what makes the probe warm the RIGHT prefix: the
// system prompt is a constant in that file, and a copy kept here would drift
// from it silently, warming a prefix nothing asks for. The import is optional —
// if it ever fails the watchdog still reports up/wedged/down from the plain
// probe, because a watchdog that stops watching over a bad path is useless.
const MODULE_PATH = process.env.CC_CLASSIFIER_MODULE
  ?? path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "local-classifier", "local-classifier.js")

async function loadClassifier() {
  try {
    process.env.CC_CLASSIFIER_LIBRARY = "1"
    const { LocalClassifier } = await import(MODULE_PATH)
    const I = LocalClassifier?.internals
    return typeof I?.classifyOnce === "function" ? I : null
  } catch { return null }
}

const HOME = os.homedir()
const CONFIG_FILE = path.join(HOME, ".config", "cc-local-classifier", "remote-watchdog.json")
const STATE_FILE = path.join(HOME, ".local", "share", "cc-local-classifier", "remote-watchdog.json")
const HISTORY_FILE = path.join(HOME, ".local", "share", "cc-local-classifier", "remote-watchdog.jsonl")

/**
 * Endpoints are tried IN ORDER and the first to answer wins. LAN first because
 * it is a couple of milliseconds away when it works; Tailscale second because
 * it is the one that still works away from home. Reporting which of the two
 * answered is the point — "up over Tailscale" and "up over LAN" mean different
 * things about where the laptop is.
 */
const DEFAULTS = Object.freeze({
  target: "macbook-claw",
  endpoints: [
    { name: "lan", url: "http://192.168.50.16:8080/v1" },
    { name: "tailscale", url: "http://100.103.38.78:8080/v1" },
  ],
  model: "mlx-community/Qwen3.5-4B-OptiQ-4bit",
  /** The model list is only ever used to tell `wedged` from `down`. */
  livenessTimeoutMs: 5_000,
  /** A cold load on that box measured 17 s, so a first probe must outlast it. */
  completionTimeoutMs: 25_000,
  /** Consecutive bad probes before the status flips. One blip is not an outage. */
  failureThreshold: 3,
  /** macOS notification on a status change. */
  notify: true,
  /**
   * Remediation over ssh. OFF until it is configured, and it stays off unless
   * BOTH `ssh` and `command` are set, because only the box knows how its server
   * is started — a default that guessed (`pkill -f mlx_lm.server`) would kill
   * the process and leave nothing to bring it back. Set `command` to whatever
   * actually relaunches it there, e.g. a `launchctl kickstart -k` of its agent.
   *
   * `minIntervalMs` is the floor between attempts. A wedge that returns
   * immediately after a restart is a problem a restart does not solve, and
   * hammering it would only bury the evidence.
   */
  restart: { enabled: false, ssh: null, command: null, minIntervalMs: 10 * 60_000 },
})

const readJson = (file) => {
  try { return JSON.parse(fs.readFileSync(file, "utf8")) } catch { return null }
}

function loadConfig() {
  const user = readJson(CONFIG_FILE)
  if (!user || typeof user !== "object") return { ...DEFAULTS }
  const out = { ...DEFAULTS, ...user }
  if (!Array.isArray(out.endpoints) || out.endpoints.length === 0) out.endpoints = DEFAULTS.endpoints
  return out
}

/** Write through a temp file so a reader never sees a half-written state. */
function writeAtomic(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true, mode: 0o700 })
  const tmp = `${file}.tmp-${process.pid}`
  fs.writeFileSync(tmp, text, { mode: 0o600 })
  fs.renameSync(tmp, file)
}

async function withTimeout(ms, fn) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), ms)
  const started = Date.now()
  try {
    const value = await fn(controller.signal)
    return { ok: true, value, latencyMs: Date.now() - started }
  } catch (e) {
    const why = e?.name === "AbortError" ? "timeout" : (e?.cause?.code ?? e?.code ?? e?.message ?? "error")
    return { ok: false, error: String(why), latencyMs: Date.now() - started }
  } finally {
    clearTimeout(timer)
  }
}

/** One endpoint: is the list there, and does a real token come back? */
async function probe(endpoint, cfg, classifier) {
  const base = endpoint.url.replace(/\/+$/, "")
  const liveness = await withTimeout(cfg.livenessTimeoutMs, async (signal) => {
    const res = await fetch(`${base}/models`, { signal })
    if (!res.ok) throw new Error(`http_${res.status}`)
    return true
  })

  const completion = classifier
    ? await warmProbe(classifier, endpoint, cfg)
    : await plainProbe(base, cfg)

  return {
    name: endpoint.name,
    url: endpoint.url,
    liveness: liveness.ok ? "ok" : liveness.error,
    completion: completion.ok ? "ok" : completion.error,
    latencyMs: completion.ok ? completion.latencyMs : null,
    answer: completion.ok ? completion.value : null,
    // Whether this probe warmed the classifier's prompt prefix, or only kept
    // the weights resident. The difference is a full ~3.2k-token prefill on the
    // next real classification, so it belongs in the state file rather than
    // being assumed.
    warmed: completion.ok ? Boolean(completion.warmed) : false,
    // Populated only on the warm path. `pSafe` is the cascade's gate input, and
    // a null here means the server answered but returned no usable logprobs —
    // which would make every primary verdict uncertain and route everything to
    // the secondary. Worth seeing before it becomes a latency mystery.
    verdict: completion.verdict ?? null,
    pSafe: completion.pSafe ?? null,
  }
}

/**
 * The real thing: the classifier's own system prompt, sent through the
 * classifier's own request path, in the shape the cascade's primary uses.
 * `true` is the subject because the rule layer has no opinion on it, so the
 * call always reaches the model.
 */
async function warmProbe(I, endpoint, cfg) {
  // Hermetic defaults, NOT the user's config: this must not pick up a cascade
  // and start asking a second model on every heartbeat.
  const base = I.resolveConfig({ readFile: () => null, env: {} }).config
  const config = {
    ...base,
    endpoint: endpoint.url,
    model: cfg.model,
    timeoutMs: cfg.completionTimeoutMs,
    cascade: null,
  }
  const started = Date.now()
  try {
    const r = await I.classifyOnce({
      kind: "bash", subject: "true", config, projectDir: null,
      timeoutMs: cfg.completionTimeoutMs, streaming: false, logprobs: true,
    })
    const latencyMs = Date.now() - started
    // A malformed answer still means the model generated tokens, so the box is
    // serving; only silence counts as a wedge.
    const answering = r.failure === null || r.failure === "malformed_output"
    if (!answering) return { ok: false, error: r.failure, latencyMs }
    return {
      ok: true, latencyMs, warmed: true,
      value: r.verdict ?? "(malformed)",
      verdict: r.verdict ?? null,
      pSafe: typeof r.pSafe === "number" ? r.pSafe : null,
    }
  } catch (e) {
    return { ok: false, error: String(e?.message ?? e), latencyMs: Date.now() - started }
  }
}

/** Fallback when the classifier module cannot be loaded: liveness only. */
async function plainProbe(base, cfg) {
  const r = await withTimeout(cfg.completionTimeoutMs, async (signal) => {
    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal,
      body: JSON.stringify({
        model: cfg.model,
        messages: [{ role: "user", content: "Reply with the single word OK." }],
        max_tokens: 4,
        temperature: 0,
        chat_template_kwargs: { enable_thinking: false },
      }),
    })
    if (!res.ok) throw new Error(`http_${res.status}`)
    const body = await res.json()
    const content = body?.choices?.[0]?.message?.content
    if (!content || !String(content).trim()) throw new Error("empty_output")
    return String(content).trim().slice(0, 40)
  })
  return { ...r, warmed: false }
}

function statusFrom(results) {
  if (results.some((r) => r.completion === "ok")) return "up"
  if (results.some((r) => r.liveness === "ok")) return "wedged"
  return "down"
}

function notify(title, message) {
  // `display notification` is built in; no extra tool to install and nothing to
  // fail if the user has never set one up. Failure here is never fatal — a
  // watchdog that cannot post a banner must still write its state file.
  const script = `display notification ${JSON.stringify(message)} with title ${JSON.stringify(title)}`
  execFile("/usr/bin/osascript", ["-e", script], () => {})
}

/**
 * Ask the box to restart its server. Every reason to decline is checked before
 * anything runs, and each is logged rather than silently skipped: a watchdog
 * that quietly does nothing looks identical to one that tried and failed.
 */
async function maybeRestart(cfg, state, previous) {
  const r = cfg.restart ?? {}
  const why = !r.enabled ? "disabled"
    : !r.ssh || !r.command ? "unconfigured"
    : (previous.lastRestart && Date.now() - Date.parse(previous.lastRestart) < (r.minIntervalMs ?? 600000)) ? "cooling down"
    : null
  if (why) {
    state.restart = { attempted: false, skipped: why, lastRestart: previous.lastRestart ?? null }
    writeAtomic(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`)
    process.stdout.write(`  restart skipped: ${why}\n`)
    return
  }
  const started = Date.now()
  const outcome = await new Promise((resolve) => {
    execFile("/usr/bin/ssh", [
      "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", r.ssh, r.command,
    ], { timeout: 60_000 }, (err, stdout, stderr) => {
      resolve(err
        ? { ok: false, error: String(err.message ?? err).split("\n")[0].slice(0, 200) }
        : { ok: true, output: String(stdout || stderr || "").trim().slice(0, 200) })
    })
  })
  state.restart = {
    attempted: true, ok: outcome.ok, at: new Date().toISOString(),
    latencyMs: Date.now() - started,
    detail: outcome.ok ? outcome.output : outcome.error,
    lastRestart: new Date().toISOString(),
  }
  state.lastRestart = state.restart.lastRestart
  writeAtomic(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`)
  process.stdout.write(`  restart ${outcome.ok ? "sent" : "FAILED"}: ${state.restart.detail || "(no output)"}\n`)
  if (cfg.notify) {
    notify(`Model box: restart ${outcome.ok ? "sent" : "failed"}`,
      `${cfg.target} was ${state.status}; ${outcome.ok ? "restart command sent" : `restart failed: ${state.restart.detail}`}`)
  }
}

async function main() {
  const cfg = loadConfig()
  const classifier = await loadClassifier()
  const now = new Date().toISOString()
  const previous = readJson(STATE_FILE) ?? {}

  const results = []
  for (const endpoint of cfg.endpoints) {
    const r = await probe(endpoint, cfg, classifier)
    results.push(r)
    // First endpoint to answer a completion wins; no reason to wake the second.
    if (r.completion === "ok") break
  }

  const observed = statusFrom(results)
  const healthy = observed === "up"
  const consecutiveFailures = healthy ? 0 : (previous.consecutiveFailures ?? 0) + 1

  // A single bad probe does not flip the reported status: the box answers over
  // Wi-Fi and one dropped request is not an outage. Recovery is NOT damped the
  // same way — one good answer means it is serving, and making the UI wait
  // three minutes to say so would be worse than useless.
  const settled = healthy || consecutiveFailures >= cfg.failureThreshold
  const status = settled ? observed : (previous.status ?? observed)
  const changed = status !== previous.status
  const answered = results.find((r) => r.completion === "ok") ?? null

  const state = {
    updated: now,
    target: cfg.target,
    status,
    observed,
    via: answered?.name ?? null,
    endpoint: answered?.url ?? null,
    model: cfg.model,
    latencyMs: answered?.latencyMs ?? null,
    // True when the probe went through the classifier's own request path and so
    // left the ~3.2k-token system prompt hot in the server's prompt cache.
    // False means the weights are resident but the next real classification
    // still pays a full prefill.
    warmed: Boolean(answered?.warmed),
    verdict: answered?.verdict ?? null,
    pSafe: answered?.pSafe ?? null,
    consecutiveFailures,
    since: changed ? now : (previous.since ?? now),
    lastOk: healthy ? now : (previous.lastOk ?? null),
    lastError: healthy ? null : (results.map((r) => `${r.name}:${r.completion}`).join(" ") || "unreachable"),
    lastRestart: previous.lastRestart ?? null,
    probes: results,
  }

  writeAtomic(STATE_FILE, `${JSON.stringify(state, null, 2)}\n`)
  try {
    fs.appendFileSync(HISTORY_FILE, `${JSON.stringify({ ts: now, status, observed, via: state.via, latencyMs: state.latencyMs, consecutiveFailures })}\n`)
  } catch {}

  // Remediation runs only on a SETTLED bad status — three consecutive failures,
  // not one blip — and only after the state file is on disk, so a restart that
  // hangs can never cost the UI its reading.
  if (settled && !healthy) await maybeRestart(cfg, state, previous)

  if (changed && cfg.notify) {
    const words = {
      up: `${cfg.target} is answering again${state.via ? ` over ${state.via}` : ""} (${state.latencyMs} ms)`,
      wedged: `${cfg.target} answers /v1/models but not completions — inference is wedged`,
      down: `${cfg.target} is not reachable`,
    }
    notify(`Model box: ${status}`, words[status] ?? status)
  }

  // One line per run, flushed, so tailing the log shows progress rather than
  // nothing until something breaks.
  process.stdout.write(`${now} ${status}${status === "up" ? ` via ${state.via} ${state.latencyMs}ms` : ` (${state.lastError})`}${changed ? "  <- CHANGED" : ""}\n`)
}

main().catch((e) => {
  // Never exit non-zero: launchd would treat a crash loop as a reason to back
  // off, and a watchdog that stops watching after a transient bug is worse than
  // one that logs the bug and tries again next minute.
  process.stdout.write(`${new Date().toISOString()} watchdog-error ${e?.message ?? e}\n`)
})
