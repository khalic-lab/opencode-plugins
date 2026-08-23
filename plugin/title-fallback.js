/**
 * opencode title-fallback — name a session that opencode failed to name.
 *
 * Why this exists. `small_model` points at Apple's on-device model on
 * 127.0.0.1:8110, whose context window is ~3.7k input tokens. opencode's
 * `SessionPrompt.ensureTitle` sends the title agent's ~525-token system prompt
 * plus the WHOLE first user message, so a first message past roughly 13 KB of
 * text comes back `400 context_length_exceeded` and the title is never set.
 * That is not retried: ensureTitle is guarded by
 * `history.filter(isRealUser).length !== 1`, so from the second message onward
 * it returns early and the session keeps `New session - <ISO>` forever.
 *
 * What this does. On `session.idle`, if a top-level session still carries the
 * default title, it generates one itself from a TRUNCATED copy of the first
 * user message — which is the one thing opencode cannot do, since it has no
 * knob to shorten what it sends. Truncation is what makes the call safe: 4000
 * characters is ~1.2k tokens against a ~3.7k ceiling, so this path cannot
 * overflow the way the one it repairs does.
 *
 * Deliberately NOT part of local-classifier.js. That plugin auto-approves
 * permission prompts in enforce mode; a cosmetic feature has no business
 * sharing its module, its config, or its failure surface. Two files, one export
 * each — the loader calls every export as a factory and one bad export can
 * poison a whole load batch.
 *
 * Failure policy: every path is wrapped and swallowed. The worst outcome this
 * plugin may ever produce is the untitled session it found. It never touches a
 * session that already has a real title, never touches a child session, and
 * never retries one it has already handled.
 *
 * Zero dependencies. The generator is a plain fetch to an OpenAI-compatible
 * /chat/completions endpoint; the rename goes through the plugin's SDK client,
 * which is the only channel available — opencode runs server and TUI in one
 * process and binds no socket to POST to.
 */

import fs from "node:fs"
import os from "node:os"
import path from "node:path"

const PLUGIN_NAME = "title-fallback"
const PLUGIN_VERSION = "0.1.0"

/**
 * opencode's own default-title test, transcribed from the 1.18.20 binary
 * (`Session.isDefaultTitle`). Only "New session - " is handled here: a
 * "Child session - " title belongs to a subagent session, which ensureTitle
 * skips on purpose and so does this.
 */
const DEFAULT_TITLE = /^New session - \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/

const DEFAULTS = {
  endpoint: "http://127.0.0.1:8110/v1",
  model: "apple/foundation-models-on-device",
  /** ~1.2k tokens of the ~3.7k the model accepts. The head, not the tail: the
   *  ask is almost always the first line and the paste is the rest. */
  maxChars: 4000,
  timeoutMs: 8000,
  logDir: path.join(os.homedir(), ".local", "share", "opencode-title-fallback"),
}

const SYSTEM_PROMPT = `You are a title generator. You output ONLY a thread title. Nothing else.

Rules:
- A single line, at most 50 characters.
- No explanations, no quotes, no trailing punctuation.
- Use the same language as the user's message.
- Keep technical terms, numbers, filenames and HTTP codes exact.
- Never answer the message or ask a question; only name it.
- Always output something, even if the input is minimal or truncated.

Examples:
why is app.js failing -> app.js failure investigation
debug 500 errors in production -> Debugging production 500 errors
@App.tsx add dark mode toggle -> Dark mode toggle in App`

// ───────────────────────────────────────────────────────────────────────────
// Logging — failures and repairs only. A session opencode titled correctly is
// the overwhelming majority and writing a line for each would bury the rest.
// ───────────────────────────────────────────────────────────────────────────

function makeLogger(logDir) {
  let broken = false
  return (event, fields) => {
    if (broken) return
    try {
      fs.mkdirSync(logDir, { recursive: true })
      const day = new Date().toISOString().slice(0, 10)
      const line = JSON.stringify({
        time: new Date().toISOString(),
        plugin: PLUGIN_NAME,
        version: PLUGIN_VERSION,
        event,
        ...fields,
      })
      fs.appendFileSync(path.join(logDir, `events-${day}.jsonl`), line + "\n")
    } catch {
      // A plugin that cannot log must still not break a session.
      broken = true
    }
  }
}

// ───────────────────────────────────────────────────────────────────────────
// Title generation
// ───────────────────────────────────────────────────────────────────────────

/** Everything the user actually typed in one message, parts joined in order. */
function userText(message) {
  const parts = message?.parts ?? []
  return parts
    .filter((p) => p?.type === "text" && !p.ignored && typeof p.text === "string")
    .map((p) => p.text)
    .join("\n")
    .trim()
}

/** opencode's own cap: >100 chars is cut to 97 plus an ellipsis. */
function capTitle(raw) {
  const line = String(raw)
    .replace(/<think>[\s\S]*?<\/think>\s*/g, "")
    .split("\n")
    .map((s) => s.trim())
    .find((s) => s.length > 0)
  if (!line) return undefined
  const cleaned = line.replace(/^["'`]+|["'`]+$/g, "").trim()
  if (!cleaned) return undefined
  return cleaned.length > 100 ? cleaned.slice(0, 97) + "..." : cleaned
}

/** What `opencode run --title` does with no value: the prompt, truncated. */
function sliceTitle(text) {
  const flat = text.replace(/\s+/g, " ").trim()
  if (!flat) return undefined
  return flat.length > 50 ? flat.slice(0, 50) + "..." : flat
}

async function generateTitle(config, text, fetchImpl = fetch) {
  const controller = new AbortController()
  const timer = setTimeout(() => controller.abort(), config.timeoutMs)
  try {
    const res = await fetchImpl(`${config.endpoint.replace(/\/$/, "")}/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      signal: controller.signal,
      body: JSON.stringify({
        model: config.model,
        temperature: 0,
        max_tokens: 48,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          { role: "user", content: `Generate a title for this conversation:\n${text.slice(0, config.maxChars)}` },
        ],
      }),
    })
    if (!res.ok) return { error: `HTTP ${res.status}` }
    const body = await res.json()
    const title = capTitle(body?.choices?.[0]?.message?.content ?? "")
    return title ? { title } : { error: "empty completion" }
  } catch (err) {
    return { error: err instanceof Error ? err.message : String(err) }
  } finally {
    clearTimeout(timer)
  }
}

// ───────────────────────────────────────────────────────────────────────────
// SDK plumbing
//
// opencode bundles two client shapes for the same route — one arg-mapped
// (`update({sessionID, title})`) and one generated (`update({path, body})`) —
// and each sends an empty payload when handed the other's. Rather than guess,
// both are attempted and the result is confirmed by reading the title back.
// ───────────────────────────────────────────────────────────────────────────

async function readSession(client, sessionID, directory) {
  const shapes = [
    () => client.session.get({ sessionID, directory }),
    () => client.session.get({ path: { id: sessionID }, query: { directory } }),
  ]
  for (const shape of shapes) {
    try {
      const info = (await shape())?.data
      if (info?.id) return info
    } catch {
      // Try the other shape.
    }
  }
  return undefined
}

async function readFirstUserMessage(client, sessionID, directory) {
  const shapes = [
    () => client.session.messages({ sessionID, directory }),
    () => client.session.messages({ path: { id: sessionID }, query: { directory } }),
  ]
  for (const shape of shapes) {
    try {
      const messages = (await shape())?.data
      if (!Array.isArray(messages)) continue
      const first = messages.find(
        (m) => m?.info?.role === "user" && !(m.parts ?? []).every((p) => p?.synthetic),
      )
      if (first) return first
    } catch {
      // Try the other shape.
    }
  }
  return undefined
}

async function writeTitle(client, sessionID, directory, title) {
  const attempts = [
    { shape: "mapped", call: () => client.session.update({ sessionID, directory, title }) },
    {
      shape: "generated",
      call: () => client.session.update({ path: { id: sessionID }, query: { directory }, body: { title } }),
    },
  ]
  for (const attempt of attempts) {
    try {
      await attempt.call()
      const after = await readSession(client, sessionID, directory)
      if (after?.title === title) return { ok: true, shape: attempt.shape }
    } catch {
      // Try the other shape.
    }
  }
  return { ok: false }
}

// ───────────────────────────────────────────────────────────────────────────
// Plugin
// ───────────────────────────────────────────────────────────────────────────

const TitleFallbackPlugin = async (input) => {
  const { client, directory } = input ?? {}
  const config = {
    ...DEFAULTS,
    endpoint: process.env.OPENCODE_TITLE_FALLBACK_ENDPOINT || DEFAULTS.endpoint,
    model: process.env.OPENCODE_TITLE_FALLBACK_MODEL || DEFAULTS.model,
    logDir: process.env.OPENCODE_TITLE_FALLBACK_LOG_DIR || DEFAULTS.logDir,
  }
  const log = makeLogger(config.logDir)
  /** Off by default: these lines fire for every session opencode titled fine,
   *  which is nearly all of them. `OPENCODE_TITLE_FALLBACK_DEBUG=1` turns them
   *  on when the question is why a repair did NOT happen. */
  const debugging = process.env.OPENCODE_TITLE_FALLBACK_DEBUG === "1"
  const debug = (event, fields) => {
    if (debugging) log(event, fields)
  }

  // One line per load. Without it "loaded but never fired" and "never loaded"
  // look identical from the log dir, and the first is the interesting one:
  // opencode reports a plugin that throws at load, but says nothing about a
  // plugin whose event never arrives.
  log("plugin.init", { endpoint: config.endpoint, model: config.model, max_chars: config.maxChars })

  /** One attempt per session per process. A session we could not repair is not
   *  retried on every subsequent idle — that would hammer the endpoint on a
   *  session the user simply left untitled. */
  const seen = new Set()

  const repair = async (sessionID) => {
    if (!client?.session || seen.has(sessionID)) return
    seen.add(sessionID)

    const info = await readSession(client, sessionID, directory)
    // Every one of these is a silent no-op in normal use — they are the
    // overwhelmingly common case. Under debug they are the only way to tell
    // "the hook ran and declined" from "the hook never ran at all".
    if (!info) return debug("declined", { session: sessionID, reason: "session unreadable" })
    if (info.parentID) return debug("declined", { session: sessionID, reason: "child session" })
    if (!DEFAULT_TITLE.test(info.title ?? "")) {
      return debug("declined", { session: sessionID, reason: "title already set", title: info.title })
    }

    const message = await readFirstUserMessage(client, sessionID, directory)
    const text = message ? userText(message) : ""
    if (!text) {
      log("skipped", { session: sessionID, reason: "no user text" })
      return
    }

    const generated = await generateTitle(config, text)
    const title = generated.title ?? sliceTitle(text)
    if (!title) {
      log("skipped", { session: sessionID, reason: "no title produced" })
      return
    }

    const written = await writeTitle(client, sessionID, directory, title)
    log(written.ok ? "repaired" : "write_failed", {
      session: sessionID,
      title,
      source: generated.title ? "model" : "slice",
      ...(generated.error ? { model_error: generated.error } : {}),
      chars: text.length,
      truncated: text.length > config.maxChars,
      ...(written.shape ? { shape: written.shape } : {}),
    })
  }

  return {
    event: async ({ event }) => {
      try {
        if (typeof event?.type === "string" && event.type.startsWith("session.")) {
          debug("event.seen", { type: event.type, session: event.properties?.sessionID ?? null })
        }
        if (event?.type !== "session.idle") return
        const sessionID = event.properties?.sessionID
        if (typeof sessionID === "string" && sessionID) await repair(sessionID)
      } catch (err) {
        // A cosmetic plugin must never surface as a session error.
        log("hook_error", { error: err instanceof Error ? err.message : String(err) })
      }
    },
  }
}

export const TitleFallback = Object.assign(TitleFallbackPlugin, {
  internals: {
    DEFAULT_TITLE,
    DEFAULTS,
    SYSTEM_PROMPT,
    capTitle,
    generateTitle,
    sliceTitle,
    userText,
  },
})
