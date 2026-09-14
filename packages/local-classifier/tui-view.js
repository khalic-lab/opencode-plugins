/**
 * The state and the words behind the classifier's on-screen box, with no
 * reference to opencode's TUI runtime — so it can be tested under `bun test`,
 * which cannot resolve @opentui/* at all. The .tsx module beside this one does
 * nothing but subscribe, tick, and draw.
 *
 * The feed is the classifier's own JSONL log rather than the event bus. That
 * costs a few milliseconds of tail latency and buys three things: the box shows
 * exactly what was recorded (no second, divergent view of the same decision),
 * the server plugin needs no changes to feed it, and a TUI that starts late
 * still ends up consistent. The event bus was never an option anyway — server
 * and TUI plugins do not share a global object, measured, even though they run
 * in one process.
 */

import fs from "node:fs"
import path from "node:path"

/**
 * How long a FINISHED permission stays on screen before the box clears — one
 * whose prompt opencode has already taken down, so the box is the only record
 * left of what was approved on the human's behalf. Long enough to read three
 * lines, which four seconds was not. Nothing else is timed against it: a
 * prompt still waiting for an answer keeps its box for as long as it waits.
 */
export const HOLD_MS = 12_000

/**
 * A long session asks for hundreds of permissions and every one of them would
 * otherwise be retained for a box that only ever draws the newest.
 */
const MAX_ENTRIES = 50

export function emptyState() {
  return { entries: [] }
}

const at = (record, now) => {
  const t = Date.parse(record?.ts ?? "")
  return Number.isFinite(t) ? t : now
}

const find = (entries, id) => entries.findIndex((e) => e.id === id)

/**
 * Fold one log record into the state. Records the box has no use for — health
 * checks, toast attempts, breaker transitions — fall through untouched.
 * @returns {object} a new state; the old one is never mutated.
 */
export function apply(state, record, now = Date.now()) {
  const id = record?.permission_id
  if (!id) return state
  // Every line carries the mode it was written under. In off mode the plugin
  // logs the ask and then does nothing with it, so a box would sit there
  // saying "classifying…" about a decision nobody is making.
  if (record.mode === "off") return state
  const entries = state.entries.slice()
  const i = find(entries, id)
  const patch = (fields) => {
    if (i < 0) return
    entries[i] = { ...entries[i], ...fields }
  }

  switch (record.event) {
    case "permission.received": {
      // Uncovered permissions (edits, webfetch) are the plugin's business to
      // log and nobody's business to draw: it never had an opinion on them.
      if (record.covered !== true) return state
      const entry = {
        id,
        command: record.metadata?.command ?? null,
        kind: record.permission ?? null,
        askedAt: at(record, now),
        verdict: null, reason: null, failure: null,
        countdownAt: null, countdownMs: null,
        decided: null, why: null, human: null,
        resolvedAt: null,
      }
      if (i < 0) entries.push(entry)
      else entries[i] = { ...entries[i], ...entry }
      break
    }
    case "decision": {
      // Schema 2 replaced `verdict`/`failure`/`skipped` with a closed-set
      // `outcome` plus `unjudged_why`. The box wants the old two fields, so
      // map back: anything that is not a verdict is a failure with a reason.
      const judged = record.outcome === "safe" || record.outcome === "risky"
      const fields = {
        verdict: judged ? record.outcome.toUpperCase() : null,
        reason: record.reason ?? null,
        failure: judged ? null : (record.unjudged_why ?? null),
      }
      // A box that started mid-flight has no "received" for this id. Showing
      // it from the classification alone beats showing nothing.
      if (i < 0) {
        entries.push({
          id, command: record.subject ?? null, kind: record.permission ?? null,
          askedAt: at(record, now), countdownAt: null, countdownMs: null,
          decided: null, why: null, human: null, resolvedAt: null, ...fields,
        })
      } else {
        patch({ ...fields, command: entries[i].command ?? record.subject ?? null })
      }
      break
    }
    case "action.countdown":
      patch({ countdownAt: at(record, now), countdownMs: record.countdown_ms ?? null })
      break
    case "action": {
      // Only two of these mean the prompt has left the screen: the plugin
      // replied ("approved"), or it found the human already had
      // ("human_won_race"). "none" — a RISKY verdict, or a classifier failure
      // — plus shadow mode's "would_approve" and a reply that never landed
      // ("approve_failed") all leave the dialog sitting exactly where it was,
      // and those are the boxes that most need to stay up beside it. Starting
      // the hold timer on them is what made a RISKY box disappear four
      // seconds into a prompt the human had not finished reading.
      const closed = record.decided === "approved" || record.decided === "human_won_race"
      patch({
        decided: record.decided ?? null,
        why: record.why ?? null,
        // Never clears one already set: `human.decision` can land first, and
        // its answer is the one that took the prompt down.
        resolvedAt: closed ? at(record, now) : (entries[i]?.resolvedAt ?? null),
      })
      break
    }
    case "self.decision":
      patch({ decided: entries[i]?.decided ?? "approved", resolvedAt: at(record, now) })
      break
    case "human.decision":
    case "human.decision.amended":
      patch({ human: record.response ?? "answered", resolvedAt: at(record, now) })
      break
    case "permission.skipped":
      // The plugin declined to classify this one; it is the human's prompt,
      // unchanged, and a box saying so would be noise.
      if (i >= 0) entries.splice(i, 1)
      break
    default:
      return state
  }

  return { entries: entries.length > MAX_ENTRIES ? entries.slice(-MAX_ENTRIES) : entries }
}

/**
 * One line, bounded. A bash permission can carry a multi-line script and an
 * external_directory ask carries two paths; either would stretch the box down
 * the screen, and the box's whole job is to be a glance.
 */
const MAX_LINE = 200

/**
 * How long an ask with no verdict stays on screen. The classifier's own
 * timeout plus its queue wait is well inside this; past it, the line that
 * would have resolved the box is not coming, and a permanent "classifying…"
 * is worse than nothing.
 *
 * A prompt waiting on the HUMAN gets no equivalent bound, and the asymmetry is
 * deliberate: the classifier promised an answer within a known timeout, so its
 * silence is a fault. A human owes nothing — the shadow logs put the median
 * reply at 25 minutes — and any deadline here would erase a box while the
 * prompt it explains is still on screen, which is the bug this replaced.
 */
const PENDING_TIMEOUT_MS = 30_000
const oneLine = (s) => {
  if (typeof s !== "string") return s ?? null
  const flat = s.replace(/\s*\n+\s*/g, " ⏎ ").trim()
  return flat.length > MAX_LINE ? flat.slice(0, MAX_LINE - 1) + "…" : flat
}

const HUMAN_VERB = { reject: "you rejected it", once: "you approved it", always: "you approved it — always" }

/**
 * The newest permission worth drawing, already turned into words. An entry
 * stays drawable until its prompt is off the screen and `holdMs` has passed;
 * a prompt still waiting on the human has no such clock.
 * @returns {{id: string, tone: string, headline: string, command: string|null, detail: string|null}|null}
 */
export function view(state, now = Date.now(), holdMs = HOLD_MS) {
  for (let i = state.entries.length - 1; i >= 0; i--) {
    const e = state.entries[i]
    if (e.resolvedAt !== null && now - e.resolvedAt > holdMs) continue
    const base = { id: e.id, command: oneLine(e.command), detail: oneLine(e.reason ?? null) }

    if (e.human) return { ...base, tone: "done", headline: HUMAN_VERB[e.human] ?? `you answered — ${e.human}` }
    if (e.decided === "approve_failed") {
      return { ...base, tone: "failed", headline: "auto-approval failed — the reply did not reach opencode" }
    }
    if (e.decided === "approved") return { ...base, tone: "done", headline: "auto-approved" }
    if (e.decided === "would_approve") return { ...base, tone: "done", headline: "would auto-approve — shadow mode" }
    if (e.why) return { ...base, tone: "failed", headline: `${e.why} — yours to answer` }
    if (e.failure) return { ...base, tone: "failed", headline: `classifier ${e.failure} — yours to answer` }
    if (e.verdict === "RISKY") return { ...base, tone: "risky", headline: "RISKY — yours to answer" }
    if (e.countdownAt !== null) {
      const left = Math.max(0, e.countdownAt + (e.countdownMs ?? 0) - now)
      return { ...base, tone: "countdown", headline: `auto-approving in ${Math.ceil(left / 1000)}s` }
    }
    if (now - e.askedAt > PENDING_TIMEOUT_MS) continue
    return { ...base, tone: "pending", headline: "classifying…" }
  }
  return null
}

/**
 * Follows the classifier's daily JSONL, reading only what was appended since
 * the last call. Every failure mode here is a silent no-op on purpose: this
 * runs inside a render loop, and a log that is missing, mid-write, rotated or
 * corrupt must cost at most one poll.
 */
export function createTailer({ dir, now = Date.now, fsImpl = fs }) {
  let file = null
  let offset = 0
  let partial = ""

  const dayFile = () => path.join(dir, `events-${new Date(now()).toISOString().slice(0, 10)}.jsonl`)
  const size = (f) => {
    try {
      return fsImpl.statSync(f).size
    } catch {
      return 0
    }
  }

  return {
    poll() {
      try {
        const want = dayFile()
        if (want !== file) {
          // Only the very first file starts at the end: what the classifier
          // decided before the TUI opened is history. A rollover mid-session is
          // the opposite — those records are this session's, so read from 0.
          const first = file === null
          file = want
          partial = ""
          offset = first ? size(want) : 0
        }
        const end = size(file)
        if (end < offset) {
          offset = 0
          partial = ""
        }
        if (end === offset) return []

        const length = end - offset
        const buf = Buffer.allocUnsafe(length)
        const fd = fsImpl.openSync(file, "r")
        try {
          fsImpl.readSync(fd, buf, 0, length, offset)
        } finally {
          fsImpl.closeSync(fd)
        }
        offset = end

        // The classifier appends synchronously but a poll can still land
        // between the two halves of a line; hold the tail until its newline.
        const lines = (partial + buf.toString("utf8")).split("\n")
        partial = lines.pop() ?? ""
        const out = []
        for (const line of lines) {
          if (!line.trim()) continue
          try {
            out.push(JSON.parse(line))
          } catch {
            // One unreadable line is not a reason to stop following the file.
          }
        }
        return out
      } catch {
        return []
      }
    },
  }
}
