/**
 * The usefulness gate, end to end through the real script.
 *
 * This gate answers one question: how many of the prompts you actually
 * answered would the plugin have taken off your hands? Enforcement is classify,
 * wait out the countdown, then reply — so an interruption is only removed when
 * the human took longer than BOTH. Counting every SAFE-and-approved ask instead
 * reports prompts as removed that the human had already answered, and on the
 * live corpus that was the difference between passing the gate and failing it.
 */
import { describe, test, expect, beforeEach, afterEach } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

const SCRIPT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "eval", "analyze-logs.mjs")
const T0 = Date.parse("2026-03-02T10:00:00.000Z")
const iso = (ms) => new Date(ms).toISOString()

let dir
beforeEach(() => { dir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-analyze-")) })
afterEach(() => { fs.rmSync(dir, { recursive: true, force: true }) })

const write = (records) => {
  const day = iso(T0).slice(0, 10)
  fs.writeFileSync(
    path.join(dir, `events-${day}.jsonl`),
    records.map((r) => JSON.stringify({ plugin: "local-classifier", v: "0.1.0", mode: "shadow", ...r })).join("\n") + "\n",
  )
}

const init = (countdownMs = 3_000) => ({
  ts: iso(T0), event: "plugin.init", config: { countdownMs, logDir: dir }, config_sources: ["defaults"],
})

/** One complete ask: classified SAFE in `latencyMs`, approved after `answeredMs`. */
const ask = (id, { latencyMs, answeredMs, verdict = "SAFE", response = "once", at = T0 }) => [
  { ts: iso(at), event: "permission.received", permission_id: id, session_id: `ses_${id}`, permission: "bash", covered: true, metadata: { command: `cmd ${id}` } },
  { ts: iso(at + latencyMs), event: "classification", permission_id: id, session_id: `ses_${id}`, permission: "bash", subject: `cmd ${id}`, verdict, reason: "r", failure: null, latency_ms: latencyMs, prompt_version: "p3" },
  { ts: iso(at + answeredMs), event: "human.decision", permission_id: id, session_id: `ses_${id}`, response, classifier_verdict: verdict, classifier_failure: null, subject: `cmd ${id}`, permission: "bash", decided: "would_approve", ms_since_ask: answeredMs },
]

const analyze = async () => {
  const p = Bun.spawn(["node", SCRIPT, dir, "--json"], { stdout: "pipe", stderr: "pipe" })
  const out = await new Response(p.stdout).text()
  await p.exited
  return JSON.parse(out)
}

describe("interruptions removable", () => {
  test("counts only the asks the plugin would have answered first", async () => {
    write([
      init(3_000),
      // Human took 5s; the plugin needs 0.8s to classify plus a 3s countdown.
      // It gets there first, so this prompt would never have been seen.
      ...ask("a", { latencyMs: 800, answeredMs: 5_000, at: T0 + 1_000 }),
      // Answered in 2s, before the countdown could even finish.
      ...ask("b", { latencyMs: 800, answeredMs: 2_000, at: T0 + 2_000 }),
      // A slow classification loses a race it would otherwise have won.
      ...ask("c", { latencyMs: 2_500, answeredMs: 5_000, at: T0 + 3_000 }),
    ])
    const s = await analyze()
    // The old calculation was safe_approved / approvals, which is 3/3 here.
    expect(s.gates.usefulness.value).toBeCloseTo(1 / 3, 5)
  })

  test("a RISKY verdict is never removable, however slow the human was", async () => {
    write([init(3_000), ...ask("a", { latencyMs: 500, answeredMs: 60_000, verdict: "RISKY" })])
    const s = await analyze()
    expect(s.gates.usefulness.value).toBe(0)
  })

  test("a shorter countdown wins races a longer one loses", async () => {
    const records = [...ask("a", { latencyMs: 800, answeredMs: 2_500 })]
    write([init(3_000), ...records])
    expect((await analyze()).gates.usefulness.value).toBe(0)
    write([init(1_000), ...records])
    expect((await analyze()).gates.usefulness.value).toBe(1)
  })

  test("an ask whose classification latency was never recorded is not counted as removed", async () => {
    write([
      init(3_000),
      { ts: iso(T0), event: "permission.received", permission_id: "a", session_id: "s", permission: "bash", covered: true, metadata: { command: "x" } },
      { ts: iso(T0 + 10), event: "classification", permission_id: "a", session_id: "s", permission: "bash", subject: "x", verdict: "SAFE", reason: "r", failure: null, latency_ms: null, cached: true, prompt_version: "p3" },
      { ts: iso(T0 + 90_000), event: "human.decision", permission_id: "a", session_id: "s", response: "once", classifier_verdict: "SAFE", classifier_failure: null, subject: "x", permission: "bash", decided: "would_approve", ms_since_ask: 90_000 },
    ])
    const s = await analyze()
    // A cache hit really would have replied instantly, but the record cannot
    // prove it — and a usefulness gate must not be flattered by a guess.
    expect(s.gates.usefulness.value).toBe(0)
  })
})
