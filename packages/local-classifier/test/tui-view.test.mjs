/**
 * The TUI box's logic, minus the drawing. Everything here is pure or plain
 * node:fs, so it runs under `bun test` without opencode's TUI runtime — which
 * is the point of keeping it out of the .tsx file: the rendering itself cannot
 * be unit-tested, and anything left inside it cannot be tested either.
 *
 * The box is fed by the classifier's own JSONL log rather than by the event
 * bus, so what it shows is what the classifier actually recorded, and the
 * classifier needs no changes to feed it.
 */
import { describe, test, expect } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { emptyState, apply, view, createTailer, HOLD_MS } from "../tui-view.js"

const T0 = 1_700_000_000_000
const iso = (ms) => new Date(ms).toISOString()

const received = (id, command, at = T0) => ({
  ts: iso(at), event: "permission.received", permission_id: id, session_id: "s1",
  permission: "bash", metadata: { command }, covered: true,
})
// Schema 2: one `decision` row, `outcome` closed-set rather than a nullable
// `verdict` beside a nullable `failure` beside a nullable `skipped`.
const classified = (id, verdict, reason, at = T0 + 2_000, extra = {}) => ({
  ts: iso(at), event: "decision", permission_id: id, session_id: "s1",
  subject: "git status", outcome: verdict ? verdict.toLowerCase() : "unjudged",
  unjudged_why: null, reason, ...extra,
})
// The countdown STARTS here. `action.reply_intent` is a different record,
// written after the wait is over as the audit line for the reply itself —
// reading that one as the start showed a box that never counted down.
const countdown = (id, countdownMs = 3_000, at = T0 + 2_100) => ({
  ts: iso(at), event: "action.countdown", permission_id: id, countdown_ms: countdownMs,
})
const intent = (id, countdownMs = 3_000, at = T0 + 5_090) => ({
  ts: iso(at), event: "action.reply_intent", permission_id: id, countdown_ms: countdownMs,
})
const action = (id, decided, at = T0 + 5_100, extra = {}) => ({
  ts: iso(at), event: "action", permission_id: id, decided, ...extra,
})

const feed = (records, now = T0) => records.reduce((s, r) => apply(s, r, now), emptyState())

describe("the box follows one permission from ask to outcome", () => {
  test("an ask with no verdict yet shows the command and says it is still classifying", () => {
    const v = view(feed([received("p1", "git status && git diff")]), T0 + 500)
    expect(v).not.toBeNull()
    expect(v.tone).toBe("pending")
    expect(v.command).toBe("git status && git diff")
    expect(v.headline).toMatch(/classif/i)
  })

  test("SAFE plus a reply intent counts down, and the seconds fall as time passes", () => {
    const s = feed([received("p1", "git status"), classified("p1", "SAFE", "read-only"), countdown("p1", 3_000)])
    const at = (ms) => view(s, T0 + 2_100 + ms)
    expect(at(0).tone).toBe("countdown")
    expect(at(0).headline).toMatch(/auto-approving in 3s/)
    expect(at(1_500).headline).toMatch(/auto-approving in 2s/)
    // The reason is the whole point of showing a box rather than a spinner.
    expect(at(0).detail).toBe("read-only")
    // It must not count below zero while the reply is in flight.
    expect(at(9_000).headline).toMatch(/auto-approving in 0s/)
  })

  test("the reply-intent record does not start a countdown — it is written when the wait is already over", () => {
    const s = feed([received("p1", "npm ci"), classified("p1", "SAFE", "ok"), intent("p1", 3_000, T0 + 5_090)])
    const v = view(s, T0 + 5_095)
    expect(v.tone).not.toBe("countdown")
    expect(v.headline).not.toMatch(/auto-approving/)
  })

  test("RISKY hands the prompt back and says so, carrying the reason", () => {
    const s = feed([received("p1", "rm -rf /"), classified("p1", "RISKY", "recursive delete of the root")])
    const v = view(s, T0 + 2_500)
    expect(v.tone).toBe("risky")
    expect(v.headline).toMatch(/yours to answer/i)
    expect(v.detail).toBe("recursive delete of the root")
  })

  test("a classifier failure is not silence — it reads as failed, in the failure tone", () => {
    const s = feed([received("p1", "npm ci"), classified("p1", null, null, T0 + 2_000, { unjudged_why: "timeout" })])
    const v = view(s, T0 + 2_500)
    expect(v.tone).toBe("failed")
    expect(v.headline).toMatch(/timeout/)
    expect(v.headline).toMatch(/yours to answer/i)
  })

  test("a refusal shows the reason the plugin gave for standing down", () => {
    const s = feed([
      received("p1", "npm ci"), classified("p1", "SAFE", "lockfile install"), countdown("p1"),
      action("p1", "none", T0 + 2_200, { why: "audit log write failed" }),
    ])
    const v = view(s, T0 + 2_300)
    expect(v.tone).toBe("failed")
    expect(v.headline).toMatch(/audit log write failed/)
  })

  test("an approval that did not reach opencode is the loudest state of all", () => {
    const s = feed([received("p1", "npm ci"), classified("p1", "SAFE", "ok"), countdown("p1"), action("p1", "approve_failed")])
    const v = view(s, T0 + 5_200)
    expect(v.tone).toBe("failed")
    expect(v.headline).toMatch(/did not reach|failed/i)
  })
})

describe("what the box shows fits in a box", () => {
  test("a multi-line command becomes one line, so the box keeps its shape", () => {
    const s = feed([received("p1", "cd ~/.ssh\ncat id_rsa")])
    const v = view(s, T0 + 100)
    expect(v.command).not.toContain("\n")
    expect(v.command).toContain("cd ~/.ssh")
    expect(v.command).toContain("cat id_rsa")
  })

  test("a very long command is cut, and shows that it was cut", () => {
    const s = feed([received("p1", "echo " + "x".repeat(500))])
    const v = view(s, T0 + 100)
    expect(v.command.length).toBeLessThanOrEqual(200)
    expect(v.command.endsWith("…")).toBe(true)
  })

  test("a rambling reason is cut the same way", () => {
    const s = feed([received("p1", "ls"), classified("p1", "RISKY", "because ".repeat(80))])
    const v = view(s, T0 + 2_500)
    expect(v.detail.length).toBeLessThanOrEqual(200)
  })
})

describe("the box gets out of the way", () => {
  test("a completed approval lingers briefly, then disappears", () => {
    const s = feed([received("p1", "npm ci"), classified("p1", "SAFE", "ok"), countdown("p1"), action("p1", "approved")])
    expect(view(s, T0 + 5_200).tone).toBe("done")
    expect(view(s, T0 + 5_100 + HOLD_MS + 1)).toBeNull()
  })

  test("a permission the plugin never covered is never drawn", () => {
    const s = feed([{ ts: iso(T0), event: "permission.received", permission_id: "p9", permission: "edit", covered: false, metadata: {} }])
    expect(view(s, T0 + 100)).toBeNull()
  })

  test("a human answering first replaces the countdown rather than leaving it ticking", () => {
    const s = feed([
      received("p1", "npm ci"), classified("p1", "SAFE", "ok"), countdown("p1", 3_000),
      { ts: iso(T0 + 2_500), event: "human.decision", permission_id: "p1", response: "reject" },
    ])
    const v = view(s, T0 + 2_600)
    expect(v.tone).toBe("done")
    expect(v.headline).toMatch(/you (answered|rejected)/i)
    expect(v.headline).not.toMatch(/auto-approving/)
  })

  test("with two asks in flight the newest is the one on screen", () => {
    const s = feed([
      received("p1", "first", T0), classified("p1", "SAFE", "a"), countdown("p1"),
      received("p2", "second", T0 + 3_000),
    ])
    expect(view(s, T0 + 3_100).command).toBe("second")
  })

  test("state does not grow without bound as a session runs", () => {
    let s = emptyState()
    for (let i = 0; i < 500; i++) {
      s = apply(s, received(`p${i}`, `cmd ${i}`, T0 + i * 1_000), T0 + i * 1_000)
      s = apply(s, action(`p${i}`, "approved", T0 + i * 1_000 + 10), T0 + i * 1_000 + 10)
    }
    expect(s.entries.length).toBeLessThanOrEqual(50)
    expect(view(s, T0 + 499_010).command).toBe("cmd 499")
  })
})

describe("the box stays quiet when the plugin has nothing to say", () => {
  test("in off mode nothing is drawn at all — the plugin is not participating", () => {
    const s = feed([{ ...received("p1", "ls"), mode: "off" }])
    expect(view(s, T0 + 100)).toBeNull()
  })

  test("shadow mode still draws, because watching it decide is the point of shadow", () => {
    const s = feed([
      { ...received("p1", "ls"), mode: "shadow" },
      { ...classified("p1", "SAFE", "read-only"), mode: "shadow" },
      { ...action("p1", "would_approve", T0 + 2_100), mode: "shadow" },
    ])
    expect(view(s, T0 + 2_200).headline).toMatch(/shadow/i)
  })

  test("a classification the breaker refused reads as a failure, not as an eternal spinner", () => {
    const s = feed([
      received("p1", "ls"),
      { ts: iso(T0 + 10), event: "decision", permission_id: "p1", subject: "git status", outcome: "unjudged", unjudged_why: "breaker_open" },
    ])
    const v = view(s, T0 + 100)
    expect(v.tone).toBe("failed")
    expect(v.headline).toMatch(/breaker_open/)
  })

  test("an ask that never gets a verdict stops being drawn instead of hanging there", () => {
    const s = feed([received("p1", "ls")])
    expect(view(s, T0 + 5_000)).not.toBeNull()
    expect(view(s, T0 + 60_000)).toBeNull()
  })
})

describe("the tailer reads the classifier's log the way a follower must", () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "lc-tui-"))
  const day = (ms) => new Date(ms).toISOString().slice(0, 10)
  const write = (dir, ms, lines) =>
    fs.appendFileSync(path.join(dir, `events-${day(ms)}.jsonl`), lines.map((l) => JSON.stringify(l)).join("\n") + "\n")

  test("the first poll skips the backlog — yesterday's commands are not news", () => {
    const dir = tmp()
    write(dir, T0, [received("old", "ancient")])
    const t = createTailer({ dir, now: () => T0 })
    expect(t.poll()).toEqual([])
    write(dir, T0, [received("new", "fresh")])
    expect(t.poll().map((r) => r.permission_id)).toEqual(["new"])
  })

  test("only the bytes appended since last time are read, not the whole file again", () => {
    const dir = tmp()
    write(dir, T0, [received("a", "one")])
    const t = createTailer({ dir, now: () => T0 })
    t.poll()
    write(dir, T0, [received("b", "two"), received("c", "three")])
    expect(t.poll().map((r) => r.permission_id)).toEqual(["b", "c"])
    expect(t.poll()).toEqual([])
  })

  test("a line still being written is not parsed as half a record", () => {
    const dir = tmp()
    const file = path.join(dir, `events-${day(T0)}.jsonl`)
    fs.writeFileSync(file, "")
    const t = createTailer({ dir, now: () => T0 })
    t.poll()
    fs.appendFileSync(file, '{"event":"permission.received","permission_id":"p1"')
    expect(t.poll()).toEqual([])
    fs.appendFileSync(file, ',"covered":true,"metadata":{"command":"ls"}}\n')
    expect(t.poll().map((r) => r.permission_id)).toEqual(["p1"])
  })

  test("it follows the file across the UTC day rollover instead of going quiet", () => {
    const dir = tmp()
    let clock = T0
    write(dir, T0, [received("today", "a")])
    const t = createTailer({ dir, now: () => clock })
    t.poll()
    clock = T0 + 30 * 60 * 60 * 1000 // next UTC day
    write(dir, clock, [received("tomorrow", "b")])
    expect(t.poll().map((r) => r.permission_id)).toEqual(["tomorrow"])
  })

  test("garbage in the log costs one line, not the whole feed", () => {
    const dir = tmp()
    const file = path.join(dir, `events-${day(T0)}.jsonl`)
    fs.writeFileSync(file, "")
    const t = createTailer({ dir, now: () => T0 })
    t.poll()
    fs.appendFileSync(file, "not json at all\n" + JSON.stringify(received("p1", "ls")) + "\n")
    expect(t.poll().map((r) => r.permission_id)).toEqual(["p1"])
  })

  test("a missing log directory is a quiet no-op, not a crash in the render loop", () => {
    const t = createTailer({ dir: "/nonexistent/local-classifier/logs", now: () => T0 })
    expect(t.poll()).toEqual([])
    expect(t.poll()).toEqual([])
  })
})

describe("a prompt the plugin refuses to answer keeps its box", () => {
  // The report that produced these: a RISKY box vanished four seconds into a
  // prompt the human had not finished reading. `action` with decided "none" is
  // the plugin saying it will NOT reply — the dialog stays exactly where it is
  // — and treating that as "resolved" started the hold timer anyway.
  test("a RISKY ask is still on screen long after the hold would have expired", () => {
    const s = feed([
      received("p1", "rm -rf build"),
      classified("p1", "RISKY", "deletes files", T0 + 800),
      action("p1", "none", T0 + 800, { verdict: "RISKY" }),
    ])
    const v = view(s, T0 + 800 + HOLD_MS * 10)
    expect(v).not.toBeNull()
    expect(v.tone).toBe("risky")
    expect(v.headline).toMatch(/RISKY/)
  })

  test("it clears once the human answers, and not before", () => {
    const records = [
      received("p1", "rm -rf build"),
      classified("p1", "RISKY", "deletes files", T0 + 800),
      action("p1", "none", T0 + 800, { verdict: "RISKY" }),
    ]
    expect(view(feed(records), T0 + 30_000).tone).toBe("risky")
    const answered = feed([
      ...records,
      { ts: iso(T0 + 30_000), event: "human.decision", permission_id: "p1", response: "reject" },
    ])
    expect(answered && view(answered, T0 + 30_100).tone).toBe("done")
    expect(view(answered, T0 + 30_000 + HOLD_MS + 1)).toBeNull()
  })

  test("a shadow-mode would-approve stays up, because the prompt is still the human's", () => {
    const s = feed([
      received("p1", "npm ci"),
      classified("p1", "SAFE", "ok", T0 + 800),
      action("p1", "would_approve", T0 + 800),
    ])
    const v = view(s, T0 + 800 + HOLD_MS * 5)
    expect(v).not.toBeNull()
    expect(v.headline).toMatch(/would auto-approve/)
  })

  test("a failed auto-approval stays up longest of all — the human has to finish it", () => {
    const s = feed([
      received("p1", "npm ci"), classified("p1", "SAFE", "ok"), countdown("p1"),
      action("p1", "approve_failed"),
    ])
    const v = view(s, T0 + 5_100 + HOLD_MS * 5)
    expect(v).not.toBeNull()
    expect(v.tone).toBe("failed")
    expect(v.headline).toMatch(/did not reach opencode/)
  })

  // `self.decision` is the one record that resolves a box the plugin did not
  // close itself, and it is right to: it is only ever written off a real
  // `permission.replied`, which means opencode has already taken the prompt
  // down — the transport erred but the server took the reply anyway. Without
  // that record the same `approve_failed` stays up, because then the prompt
  // really is still sitting there.
  test("approve_failed clears only once opencode confirms it took the reply", () => {
    const base = [received("p1", "npm ci"), classified("p1", "SAFE", "ok"), countdown("p1"), action("p1", "approve_failed")]
    expect(view(feed(base), T0 + 5_100 + HOLD_MS * 5).tone).toBe("failed")

    const confirmed = feed([
      ...base,
      { ts: iso(T0 + 5_150), event: "self.decision", permission_id: "p1", response: "once" },
    ])
    expect(view(confirmed, T0 + 5_200).tone).toBe("failed")
    expect(view(confirmed, T0 + 5_150 + HOLD_MS + 1)).toBeNull()
  })

  test("the hold is long enough to read three lines", () => {
    expect(HOLD_MS).toBeGreaterThanOrEqual(10_000)
  })
})
