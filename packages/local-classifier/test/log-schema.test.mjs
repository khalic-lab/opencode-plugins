/**
 * The log row IS the contract. Everything that reads this classifier's output
 * — the TUI box, eval/analyze-logs.mjs, whatever asks "how is it doing" next
 * month — reads these fields and nothing else, so the shape gets tests of its
 * own rather than being an emergent property of whoever last edited a call
 * site.
 *
 * Schema 2 exists because schema 1 could not answer "how much traffic got
 * judged": `classification` covered verdicts, breaker skips, busy skips,
 * over-length subjects and cache hits alike, and the intent lived on a
 * separate `action` row that also covered tools the classifier never claimed.
 * Three events, three denominators. The tests below pin the three properties
 * that fixed it.
 */
import { describe, test, expect } from "bun:test"
import { LocalClassifier } from "../local-classifier.js"

const { LOG_SCHEMA, decisionFields, attemptsOf, subjectSha } = LocalClassifier.internals
const CONFIG = { endpoint: "http://box:8080/v1", model: "qwen" }

describe("the decision row's outcome is a closed set", () => {
  const outcomeOf = (result) =>
    decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result }).outcome

  test("a verdict becomes its lowercase self and nothing else does", () => {
    expect(outcomeOf({ verdict: "SAFE" })).toBe("safe")
    expect(outcomeOf({ verdict: "RISKY" })).toBe("risky")
  })

  test("every way of not reaching a verdict lands on one value, with the cause beside it", () => {
    // This is the property the old schema lacked. A breaker skip and a
    // timeout are different causes but the SAME fact for counting: nothing
    // was judged. Reading `unjudged_why` is opt-in; reading `outcome` is not.
    for (const why of ["breaker_open", "busy", "too_long", "timeout", "http_503", "malformed_output"]) {
      const row = decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result: { verdict: null, failure: why } })
      expect(row.outcome).toBe("unjudged")
      expect(row.unjudged_why).toBe(why)
    }
  })

  test("a skip that never called the model reads the same as one that did", () => {
    const row = decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result: { skipped: "breaker_open" } })
    expect(row.outcome).toBe("unjudged")
    expect(row.unjudged_why).toBe("breaker_open")
  })

  test("the verdict and the gate's intent are separate fields — a RISKY can still be a pass", () => {
    const row = decisionFields({
      kind: "bash", subject: "rm -rf /", config: CONFIG,
      result: { verdict: "RISKY", reason: "recursive delete" },
      decided: "pass", why: "classified RISKY — left to the built-in classifier",
    })
    expect(row.outcome).toBe("risky")
    expect(row.decided).toBe("pass")
  })
})

describe("attempts[] is always there, because the case you need it for is the one you did not predict", () => {
  test("a single-address primary still gets a row, carrying the config's endpoint", () => {
    // `primary.endpoint` is only stamped when there was a choice of address.
    // Without the default the column would be null in the common case, which
    // is the case you read most.
    const a = attemptsOf({ primary: { verdict: "SAFE", latencyMs: 900, failure: null, pSafe: 0.9999 } }, CONFIG.endpoint)
    expect(a).toEqual([{ role: "primary", endpoint: CONFIG.endpoint, model: null, ms: 900, failure: null, p_safe: 0.9999, p_risky: null }])
  })

  test("every address tried appears, and the scores land on the attempt that answered", () => {
    const a = attemptsOf({
      primary: {
        verdict: "SAFE", latencyMs: 1200, failure: null, pSafe: 0.9995, pRisky: 0.0004,
        endpoint: "http://b/v1",
        attempts: [
          { endpoint: "http://a/v1", failure: "fetch_error:EHOSTUNREACH", latencyMs: 30 },
          { endpoint: "http://b/v1", failure: null, latencyMs: 1200 },
        ],
      },
    }, CONFIG.endpoint)
    expect(a.map((x) => x.endpoint)).toEqual(["http://a/v1", "http://b/v1"])
    expect(a[0].failure).toBe("fetch_error:EHOSTUNREACH")
    expect(a[0].p_safe).toBeNull()
    expect(a[1].p_safe).toBe(0.9995)
  })

  test("the secondary is its own attempt at its own address", () => {
    const a = attemptsOf({
      primary: { verdict: null, failure: "timeout", latencyMs: 4000 },
      secondary: { verdict: "SAFE", failure: null, latencyMs: 500, endpoint: "http://flash/v1" },
    }, CONFIG.endpoint)
    expect(a.map((x) => x.role)).toEqual(["primary", "secondary"])
    expect(a[1].endpoint).toBe("http://flash/v1")
  })

  test("no model asked means no attempts, not a missing field", () => {
    const row = decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result: { skipped: "breaker_open" } })
    expect(row.attempts).toEqual([])
  })
})

describe("the row carries what an analyzer needs and not a byte more", () => {
  test("the raw completion is kept only when it is the finding", () => {
    // 4 kB of completion text on every row, and again on a tail row, was most
    // of the 8.8 MB the log wrote on 2026-09-08. On a parse failure the text
    // IS the evidence, so it stays.
    const ok = decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result: { verdict: "SAFE", raw: "VERDICT: SAFE\nREASON: fine" } })
    expect(ok.raw).toBeNull()
    const bad = decisionFields({ kind: "bash", subject: "git status", config: CONFIG, result: { verdict: null, failure: "malformed_output", raw: "I think perhaps" } })
    expect(bad.raw).toBe("I think perhaps")
  })

  test("subject_sha is stable across runs, so a command labelled once joins forever", () => {
    expect(subjectSha("git status")).toBe(subjectSha("git status"))
    expect(subjectSha("git status")).not.toBe(subjectSha("git status "))
    expect(subjectSha("git status")).toMatch(/^[0-9a-f]{16}$/)
  })

  test("a cache hit is marked and contributes no latency sample", () => {
    const row = decisionFields({
      kind: "bash", subject: "git status", config: CONFIG, cached: true,
      result: { verdict: "SAFE", cascadeMs: null, latencyMs: null },
    })
    expect(row.cached).toBe(true)
    expect(row.ms).toBeNull()
  })

  test("queue depth rides on the row — saturation should not have to be inferred from a timeout rate", () => {
    const row = decisionFields({
      kind: "bash", subject: "git status", config: CONFIG,
      result: { verdict: "SAFE", cascadeMs: 900 },
      queue: { waitMs: 120, depth: 3, inFlight: 2 },
    })
    expect(row.queue_depth).toBe(3)
    expect(row.queue_wait_ms).toBe(120)
    expect(row.in_flight).toBe(2)
  })
})

test("the schema stamps itself, so a parser never has to guess from the plugin version", () => {
  expect(LOG_SCHEMA).toBe(2)
})

describe("provenance: the model that ANSWERED, not the one we asked for", () => {
  // Measured 2026-09-09: the remote box's mlx_lm.server ignores the request's
  // `model` field. It lists four models at /v1/models, serves whichever is
  // resident, answers a bogus name without complaint, and echoes the resident
  // name back. Two eval runs that differed only in the requested model
  // produced byte-identical results before this was noticed.
  test("the served name wins over the configured one", () => {
    const a = attemptsOf({
      primary: { verdict: "SAFE", latencyMs: 900, failure: null, servedModel: "mlx-community/Qwen3.5-2B-MLX-4bit" },
    }, CONFIG.endpoint)
    expect(a[0].model).toBe("mlx-community/Qwen3.5-2B-MLX-4bit")
  })

  test("the configured name is the fallback, not the source of truth", () => {
    const a = attemptsOf({
      secondary: { verdict: "SAFE", latencyMs: 500, failure: null, endpoint: "http://flash/v1", model: "flash-next", servedModel: null },
    }, CONFIG.endpoint)
    expect(a[0].model).toBe("flash-next")
  })

  test("a server that says nothing leaves a null, never a guess", () => {
    const a = attemptsOf({ primary: { verdict: null, failure: "timeout", latencyMs: 4000 } }, CONFIG.endpoint)
    expect(a[0].model).toBeNull()
  })
})
