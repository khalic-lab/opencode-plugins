/**
 * The three-stage decision: rules, then the primary with its confidence, then
 * the secondary.
 *
 * Two request-shape assertions carry more weight than the rest and are worth
 * naming here, because both were measured against the real servers on
 * 2026-09-04 and both are silent when they break:
 *   - the primary is asked NON-streaming with logprobs, because mlx_lm drops
 *     logprobs from streamed chunks and the confidence simply never arrives;
 *   - the secondary is asked with NO logprobs key at all, because mtplx
 *     answers an HTTP error to one, which would take out the stage that
 *     decides every hard case.
 */

import { describe, test, expect } from "bun:test"
import { LocalClassifier } from "../local-classifier.js"

const { classify, resolveConfig, verdictConfidence, CASCADE_DEFAULTS } = LocalClassifier.internals

const PROJ = "/usr/local/src/webapp-142"
const SECONDARY = { endpoint: "http://127.0.0.1:7777/proxy/flash/v1", model: "flash-next" }

const baseConfig = {
  endpoint: "http://127.0.0.1:8199/v1",
  model: "qwen-4b",
  timeoutMs: 10_000,
  maxTokens: 160,
  temperature: 0,
  stream: true,
  tailTimeoutMs: 5_000,
  rules: { enabled: true },
  cascade: null,
}

const withCascade = (over = {}) => ({
  ...baseConfig,
  cascade: { secondary: SECONDARY, ...CASCADE_DEFAULTS, ...over },
})

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * The verdict token of a REAL answer, captured on 2026-09-04 from
 * mlx-community/Qwen3.5-4B-OptiQ-4bit at 127.0.0.1:8199 for `git status`
 * (top_logprobs: 8). Trimmed to the tokens up to the verdict — the ones the
 * parser walks — with the reason's tokens dropped.
 *
 * Note the shapes the parser has to survive: the keyword arrives as
 * "VER"+"D"+"ICT"+":" so no single token equals "VERDICT:", the verdict itself
 * carries a leading "Ġ", and the alternatives include "SAFE" with no prefix,
 * lowercase "Ġsafe", and "_SAFE", which is NOT a SAFE vote.
 */
const REAL_CERTAIN_SAFE = [
  { token: "VER", logprob: 0 },
  { token: "D", logprob: 0 },
  { token: "ICT", logprob: 0 },
  { token: ":", logprob: 0 },
  {
    token: "ĠSAFE",
    logprob: 0,
    top_logprobs: [
      { token: "ĠSAFE", logprob: 0 },
      { token: "ĠR", logprob: -9.25 },
      { token: "SAFE", logprob: -11.75 },
      { token: "ĠSafe", logprob: -13 },
      { token: "ĠVER", logprob: -13.25 },
      { token: "Ġsafe", logprob: -13.5625 },
      { token: "ĠSAVE", logprob: -14.6875 },
      { token: "_SAFE", logprob: -14.6875 },
    ],
  },
]

/**
 * The same shape one rung down the 4B's grid: pSAFE 0.883, pRISKY 0.117. The
 * grid (1.00, 0.88, 0.78, 0.69 …) is why `certain` defaults to 0.999 — 0.88 is
 * the score the held-out false-SAFEs sat at, not a near-miss.
 */
const UNCERTAIN_SAFE = [
  { token: "VER", logprob: 0 },
  { token: "D", logprob: 0 },
  { token: "ICT", logprob: 0 },
  { token: ":", logprob: 0 },
  {
    token: "ĠSAFE",
    logprob: -0.1244,
    top_logprobs: [
      { token: "ĠSAFE", logprob: -0.1244 }, // e^-0.1244 = 0.883
      { token: "ĠR", logprob: -2.1456 },    // e^-2.1456 = 0.117
    ],
  },
]

// ---------------------------------------------------------------------------
// A fetch that records every request and answers per endpoint.
// ---------------------------------------------------------------------------

const jsonAnswer = (content, logprobsContent = null) => ({
  ok: true,
  status: 200,
  headers: new Headers({ "content-type": "application/json" }),
  json: async () => ({
    choices: [{ message: { content }, ...(logprobsContent ? { logprobs: { content: logprobsContent } } : {}) }],
  }),
})

/** An SSE answer, the shape the secondary's streaming path reads. */
const sseAnswer = (chunks) => {
  const enc = new TextEncoder()
  const body = new ReadableStream({
    start(controller) {
      for (const text of chunks) {
        controller.enqueue(enc.encode(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`))
      }
      controller.enqueue(enc.encode("data: [DONE]\n\n"))
      controller.close()
    },
  })
  return { ok: true, status: 200, headers: new Headers({ "content-type": "text/event-stream" }), body }
}

/**
 * `routes` maps a substring of the URL to a handler. Every call is recorded
 * with its parsed body, so a test can assert on what was actually sent.
 */
const recorder = (routes) => {
  const calls = []
  const fetchImpl = async (url, init) => {
    const body = JSON.parse(init.body)
    calls.push({ url, body, init })
    for (const [needle, handler] of Object.entries(routes)) {
      if (url.includes(needle)) return typeof handler === "function" ? handler(body, init) : handler
    }
    throw new Error(`no route for ${url}`)
  }
  return { calls, fetchImpl }
}

const PRIMARY_HOST = "8199"
const SECONDARY_HOST = "7777"

// ---------------------------------------------------------------------------

describe("verdictConfidence — the logprobs of a real answer", () => {
  test("a captured certain-SAFE response reads as pSAFE 1.0", () => {
    const { pSafe, pRisky } = verdictConfidence(REAL_CERTAIN_SAFE)
    expect(pSafe).toBeGreaterThan(0.999)
    expect(pRisky).toBeLessThan(0.001)
  })
  test("the grid's next rung down reads as 0.883", () => {
    const { pSafe, pRisky } = verdictConfidence(UNCERTAIN_SAFE)
    expect(pSafe).toBeCloseTo(0.883, 3)
    expect(pRisky).toBeCloseTo(0.117, 3)
  })
  test("no logprobs, a truncated answer, or junk all read as no confidence", () => {
    expect(verdictConfidence(null)).toEqual({ pSafe: null, pRisky: null })
    expect(verdictConfidence(undefined)).toEqual({ pSafe: null, pRisky: null })
    expect(verdictConfidence([])).toEqual({ pSafe: null, pRisky: null })
    // The keyword is there but the answer stopped before the verdict token.
    expect(verdictConfidence(REAL_CERTAIN_SAFE.slice(0, 4))).toEqual({ pSafe: null, pRisky: null })
    // The verdict token is there but carries no alternatives.
    expect(verdictConfidence([{ token: "VERDICT:" }, { token: " SAFE" }])).toEqual({ pSafe: null, pRisky: null })
  })
})

describe("stage 1 — the rules short-circuit", () => {
  test("a rule hit is the verdict, and no request is made at all", async () => {
    const { calls, fetchImpl } = recorder({})
    const r = await classify({
      kind: "bash", subject: "git push --force-with-lease origin main",
      config: withCascade(), projectDir: PROJ, fetchImpl,
    })
    expect(calls.length).toBe(0)
    expect(r.verdict).toBe("RISKY")
    expect(r.stage).toBe("rules")
    expect(r.rule).toBe("force-push")
    expect(r.reason).toContain("(rule: force-push)")
    expect(r.failure).toBeNull()
    expect(r.rest).toBeNull()
    expect(r.primary).toBeNull()
    expect(r.secondary).toBeNull()
  })

  test("the new env-dump rule reaches the classifier through the same path", async () => {
    const { calls, fetchImpl } = recorder({})
    const r = await classify({ kind: "bash", subject: "printenv", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(0)
    expect(r.rule).toBe("env-dump")
  })

  test("rules: { enabled: false } sends the same command to the model", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: RISKY\nREASON: rewrites a published branch"),
      [SECONDARY_HOST]: jsonAnswer("VERDICT: RISKY\nREASON: force push"),
    })
    const r = await classify({
      kind: "bash", subject: "git push --force origin main",
      config: { ...withCascade(), rules: { enabled: false } }, projectDir: PROJ, fetchImpl,
    })
    expect(calls.length).toBe(2)
    expect(r.stage).toBe("secondary")
    expect(r.rule).toBeNull()
  })

  test("rules never run for an external_directory subject — it is a path list, not a command", async () => {
    // `~/.ssh/id_rsa` would be a credential-kinds hit if it were read as a
    // shell command; as a directory subject it must reach the model.
    const { calls, fetchImpl } = recorder({ [PRIMARY_HOST]: jsonAnswer("VERDICT: RISKY\nREASON: private key", REAL_CERTAIN_SAFE) })
    const r = await classify({
      kind: "external_directory", subject: "/Users/dev/.ssh/id_rsa",
      config: { ...baseConfig, stream: false }, projectDir: PROJ, fetchImpl,
    })
    expect(calls.length).toBe(1)
    expect(r.stage).toBe("primary")
    expect(r.verdict).toBe("RISKY")
  })
})

describe("stage 2 — the primary and its confidence", () => {
  test("a certain SAFE ends the cascade: one call, non-streaming, logprobs asked for", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(1)
    expect(calls[0].url).toContain(PRIMARY_HOST)
    expect(calls[0].body.stream).toBe(false)
    expect(calls[0].body.logprobs).toBe(true)
    expect(calls[0].body.top_logprobs).toBe(8)
    expect(calls[0].body.model).toBe("qwen-4b")
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("primary")
    expect(r.reason).toBe("read-only")
    expect(r.primary.pSafe).toBeGreaterThan(0.999)
    expect(r.secondary).toBeNull()
  })

  test("a SAFE at 0.883 is not certain and goes to the secondary", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: looks fine", UNCERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: RISKY\n", "REASON: rewrites history"]),
    })
    const r = await classify({ kind: "bash", subject: "go mod download all", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("RISKY")
    expect(r.primary.verdict).toBe("SAFE")
    expect(r.primary.pSafe).toBeCloseTo(0.883, 3)
    expect(r.secondary.verdict).toBe("RISKY")
    expect(r.secondary.model).toBe("flash-next")
  })

  test("a SAFE with no logprobs in the response is not certain either", async () => {
    // A server that ignores the logprobs field must not read as a perfect
    // score — pSafe null is "unknown", and unknown goes on to stage 3.
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: read-only"),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]),
    })
    const r = await classify({ kind: "bash", subject: "sed -n 1,5p /etc/hosts", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.stage).toBe("secondary")
    expect(r.primary.pSafe).toBeNull()
    expect(r.verdict).toBe("SAFE")
  })

  test("a RISKY primary goes to the secondary too — the second opinion decides both ways", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: RISKY\nREASON: deletes a directory", REAL_CERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: the directory is build output"]),
    })
    const r = await classify({ kind: "bash", subject: "rm -rf ./coverage", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.primary.verdict).toBe("RISKY")
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("secondary")
  })

  test("a malformed primary answer goes to the secondary rather than failing the call", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("I think this is fine!"),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: RISKY\n", "REASON: unclear"]),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.primary.failure).toBe("malformed_output")
    expect(r.verdict).toBe("RISKY")
  })

  test("an unreachable primary still gets a verdict out of the secondary", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: () => { throw new Error("ECONNREFUSED") },
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.primary.failure).toMatch(/^fetch_error:/)
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("secondary")
  })
})

describe("stage 2 — endpointFallbacks: the same primary at more addresses", () => {
  const LAN = "http://192.168.50.16:8080/v1"
  const TS = "http://100.103.38.78:8080/v1"
  const withFallback = (over = {}) => ({ ...withCascade(over), endpoint: LAN, endpointFallbacks: [TS] })

  test("an unreachable first address falls through, and the record names the one that answered", async () => {
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": () => { throw new Error("connect EHOSTUNREACH 192.168.50.16:8080") },
      "100.103.38.78": jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(2)
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("primary")
    expect(r.primary.endpoint).toBe(TS)
  })

  test("a timeout does NOT move on — a busy server is not an unreachable address", async () => {
    // The shadow window of 2026-09-06..09: both addresses were routes to one
    // mlx_lm process, so a timeout at the first meant BUSY and the retry
    // asked the same saturated server again — 1,533 double-timeouts, and the
    // secondary starved to its 2 s floor. The second address is never tried.
    const hang = (_body, init) => new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => { const e = new Error("aborted"); e.name = "AbortError"; reject(e) })
    })
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": hang,
      "100.103.38.78": jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: second opinion"]),
    })
    const config = { ...withFallback({ primaryTimeoutMs: 150 }), timeoutMs: 3000 }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    expect(calls.some((c) => c.url.includes("100.103.38.78"))).toBe(false)
    expect(r.primary.failure).toBe("timeout")
    // The whole point of not retrying: stage 3 still has budget and decides.
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("SAFE")
  })

  test("a 5xx falls through; a 4xx does not — that server answers the same at every address", async () => {
    // 502, not 503. A 503 on this fleet means "busy, retry" and is handled as
    // a load signal in its own describe block below; 502 is the proxy/crashed
    // -worker case a second route can genuinely fix.
    const five = recorder({
      "192.168.50.16": { ok: false, status: 502, headers: new Headers() },
      "100.103.38.78": jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl: five.fetchImpl })
    expect(r.primary.endpoint).toBe(TS)
    expect(r.verdict).toBe("SAFE")

    const four = recorder({
      "192.168.50.16": { ok: false, status: 404, headers: new Headers() },
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]),
    })
    const r2 = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl: four.fetchImpl })
    expect(four.calls.some((c) => c.url.includes("100.103.38.78"))).toBe(false)
    expect(r2.primary.failure).toBe("http_404")
    expect(r2.stage).toBe("secondary")
  })

  test("a malformed answer does not fall through — a different address will not parse better", async () => {
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": jsonAnswer("no verdict here"),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: RISKY\n", "REASON: because"]),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl })
    expect(calls.some((c) => c.url.includes("100.103.38.78"))).toBe(false)
    expect(r.primary.failure).toBe("malformed_output")
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("RISKY")
  })

  test("an uncertain SAFE does not fall through either — it is an answer, and the secondary's case", async () => {
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: RISKY\n", "REASON: second opinion"]),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl })
    expect(calls.some((c) => c.url.includes("100.103.38.78"))).toBe(false)
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("RISKY")
  })

  test("blackholing addresses cannot starve the secondary — 2 s stays reserved, and the row keeps every attempt", async () => {
    // Injected clock: each primary attempt eats its whole slice. With two
    // fallbacks and no reserve, stage 2 would spend 3 × 4000 of the 10 000
    // budget and stage 3 would never run (`secondary_no_budget`).
    let clock = 0
    const now = () => clock
    // A transport failure, not a timeout — since 2026-09-09 only these move
    // the primary along, so only these can spend the budget on N addresses.
    const eat = (ms) => () => { clock += ms; throw new Error("connect EHOSTUNREACH") }
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": eat(4000),
      "100.103.38.78": eat(4000),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]),
    })
    const config = { ...withFallback(), endpointFallbacks: [TS, "http://100.103.38.79:8080/v1"] }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl, now })
    // Two primary attempts, then the loop stops: 10000 − 8000 leaves exactly
    // the reserve, so the third address is never tried and the secondary runs.
    expect(calls.filter((c) => c.url.includes("8080")).length).toBe(2)
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("SAFE")
    expect(r.primary.attempts).toEqual([
      { endpoint: LAN, failure: "fetch_error:connect EHOSTUNREACH", latencyMs: 4000 },
      { endpoint: TS, failure: "fetch_error:connect EHOSTUNREACH", latencyMs: 4000 },
    ])
    expect(r.primary.endpoint).toBe(TS)
  })

  test("a timeout DOES move on when the next address declares itself a separate failure domain", async () => {
    // The ANE backend is a different machine's runtime on the same host: a
    // wedged remote answers TCP and hangs, so it fails as a timeout, and that
    // is exactly the case the local backend exists to catch. Opt-in per
    // address, because two routes to ONE server must keep the old behaviour.
    const hang = (_body, init) => new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => { const e = new Error("aborted"); e.name = "AbortError"; reject(e) })
    })
    const ANE = "http://127.0.0.1:8123/v1"
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": hang,
      "127.0.0.1:8123": jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const config = {
      ...withCascade({ primaryTimeoutMs: 150 }), timeoutMs: 3000, endpoint: LAN,
      endpointFallbacks: [{ endpoint: ANE, onTimeout: true, timeoutMs: 400 }],
    }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    expect(calls.some((c) => c.url.includes("8123"))).toBe(true)
    expect(r.stage).toBe("primary")
    expect(r.primary.endpoint).toBe(ANE)
    expect(r.primary.attempts.map((a) => a.failure)).toEqual(["timeout", null])
  })

  test("an address that does not serve this kind is never tried — an unanchored prompt would run cold", async () => {
    const ANE = "http://127.0.0.1:8123/v1"
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": () => { throw new Error("connect EHOSTUNREACH") },
      "127.0.0.1:8123": jsonAnswer("VERDICT: SAFE\nREASON: fine", REAL_CERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: second opinion"]),
    })
    const config = {
      ...withCascade(), endpoint: LAN,
      endpointFallbacks: [{ endpoint: ANE, onTimeout: true, kinds: ["bash"] }],
    }
    const r = await classify({ kind: "external_directory", subject: "/etc", config, projectDir: PROJ, fetchImpl })
    expect(calls.some((c) => c.url.includes("8123"))).toBe(false)
    expect(r.stage).toBe("secondary")
  })

  test("a per-address timeoutMs overrides the shared primary budget", async () => {
    let clock = 0
    const now = () => clock
    const eat = (ms) => () => { clock += ms; const e = new Error("slow"); e.name = "AbortError"; throw e }
    const ANE = "http://127.0.0.1:8123/v1"
    const { fetchImpl } = recorder({
      "192.168.50.16": eat(3000),
      "127.0.0.1:8123": eat(4500),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: second opinion"]),
    })
    const config = {
      ...withCascade({ primaryTimeoutMs: 3000 }), timeoutMs: 10_000, endpoint: LAN,
      endpointFallbacks: [{ endpoint: ANE, onTimeout: true, timeoutMs: 4500 }],
    }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl, now })
    // 3000 remote + 4500 ANE = 7500, leaving 2500 — more than the 2 s reserve,
    // so stage 3 still runs. The ANE got 4500, not the shared 3000.
    expect(r.primary.attempts.map((a) => a.latencyMs)).toEqual([3000, 4500])
    expect(r.stage).toBe("secondary")
  })

  test("a 200 whose body cannot be read is the address's failure — a captive portal, not the model", async () => {
    const { fetchImpl } = recorder({
      "192.168.50.16": {
        ok: true, status: 200, headers: new Headers({ "content-type": "text/html" }),
        json: async () => { throw new Error("Unexpected token '<'") },
      },
      "100.103.38.78": jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("primary")
    expect(r.primary.endpoint).toBe(TS)
  })

  test("every address dead → the secondary still decides", async () => {
    const { calls, fetchImpl } = recorder({
      "192.168.50.16": () => { throw new Error("ECONNREFUSED") },
      "100.103.38.78": () => { throw new Error("ECONNREFUSED") },
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withFallback(), projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(3)
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("SAFE")
    expect(r.primary.failure).toMatch(/^fetch_error:/)
  })

  test("no fallbacks configured: the primary record carries no endpoint column", async () => {
    const { fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(r.primary.endpoint).toBeUndefined()
  })

  test("resolveConfig: junk entries are dropped and reported; a non-array whole is dropped", () => {
    const readFile = (f) => (f.includes(".config/opencode/") ? { endpointFallbacks: [TS, 7, ""] } : null)
    const { config, problems } = resolveConfig({ readFile, env: {} })
    // A bare URL normalizes to the conservative address: its own budget
    // unset, and NOT retried after a timeout.
    expect(config.endpointFallbacks).toEqual([{ endpoint: TS, model: null, timeoutMs: null, onTimeout: false, kinds: null }])
    expect(problems.some((p) => /endpointFallbacks/.test(p))).toBe(true)
    const bad = resolveConfig({ readFile: (f) => (f.includes(".config/opencode/") ? { endpointFallbacks: "not-a-list" } : null), env: {} })
    expect(bad.config.endpointFallbacks).toEqual([])
    expect(bad.problems.some((p) => /endpointFallbacks/.test(p))).toBe(true)
  })

  test("a PROJECT file may not add fallback addresses", () => {
    const readFile = (f) => (f.startsWith("/w/") ? { endpointFallbacks: ["http://evil/v1"] } : null)
    const { config, problems } = resolveConfig({ worktree: "/w", readFile, env: {} })
    expect(config.endpointFallbacks).toEqual([])
    expect(problems.some((p) => /endpointFallbacks/.test(p))).toBe(true)
  })
})

describe("stage 3 — the secondary decides, and never sees a logprobs field", () => {
  test("the secondary's request is the ordinary streaming one, with no logprobs key", async () => {
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: fine"]),
    })
    await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    const sent = calls[1].body
    expect(calls[1].url).toContain(SECONDARY_HOST)
    expect(sent.model).toBe("flash-next")
    expect(sent.stream).toBe(true)
    expect("logprobs" in sent).toBe(false)
    expect("top_logprobs" in sent).toBe(false)
    expect(sent.chat_template_kwargs).toEqual({ enable_thinking: false })
  })

  test("a failing secondary is a failure — never the primary's uncertain SAFE", async () => {
    const { fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE),
      [SECONDARY_HOST]: { ok: false, status: 503 },
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBeNull()
    expect(r.failure).toBe("http_503")
    expect(r.stage).toBe("secondary")
    expect(r.primary.verdict).toBe("SAFE")
    expect(r.secondary.failure).toBe("http_503")
  })

  test("mtplx refusing logprobs would look like this, and it never happens", async () => {
    // The guard is the assertion above (`"logprobs" in sent` is false); this
    // is what the stage would return if the field ever leaked back in.
    const { fetchImpl } = recorder({
      [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE),
      [SECONDARY_HOST]: (body) => (("logprobs" in body) ? { ok: false, status: 400 } : sseAnswer(["VERDICT: SAFE\n"])),
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(r.failure).toBeNull()
    expect(r.verdict).toBe("SAFE")
  })
})

describe("the budget is shared, not doubled", () => {
  test("a primary that times out leaves the secondary the rest of the budget", async () => {
    const hang = (_body, init) => new Promise((_, reject) => {
      init.signal.addEventListener("abort", () => {
        const e = new Error("aborted"); e.name = "AbortError"; reject(e)
      })
    })
    const { calls, fetchImpl } = recorder({ [PRIMARY_HOST]: hang, [SECONDARY_HOST]: hang })
    const config = { ...withCascade({ primaryTimeoutMs: 150 }), timeoutMs: 400 }
    const t0 = Date.now()
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    const elapsed = Date.now() - t0
    expect(calls.length).toBe(2)
    expect(r.primary.failure).toBe("timeout")
    expect(r.secondary.failure).toBe("timeout")
    expect(r.verdict).toBeNull()
    // Both stages inside ONE budget: the secondary must not start a fresh
    // 400 ms of its own on top of the primary's 150.
    expect(elapsed).toBeGreaterThanOrEqual(350)
    expect(elapsed).toBeLessThan(700)
  })

  test("a primary that eats the whole budget leaves the secondary none, and says so", async () => {
    // The injected clock jumps past the deadline while the primary answers.
    let clock = 0
    const now = () => clock
    const { calls, fetchImpl } = recorder({
      [PRIMARY_HOST]: () => { clock += 11_000; return jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE) },
    })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl, now })
    expect(calls.length).toBe(1)
    expect(r.verdict).toBeNull()
    expect(r.failure).toBe("secondary_no_budget")
    expect(r.stage).toBe("secondary")
    expect(r.secondary.endpoint).toBe(SECONDARY.endpoint)
  })
})

describe("a cascade with no secondary — confidence alone", () => {
  const soloCascade = { ...baseConfig, cascade: { secondary: null, ...CASCADE_DEFAULTS } }

  test("an uncertain SAFE becomes RISKY, naming the score", async () => {
    const { calls, fetchImpl } = recorder({ [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: fine", UNCERTAIN_SAFE) })
    const r = await classify({ kind: "bash", subject: "git status", config: soloCascade, projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(1)
    expect(r.verdict).toBe("RISKY")
    expect(r.reason).toBe("primary not certain (pSAFE=0.88)")
    expect(r.stage).toBe("primary")
    expect(r.primary.verdict).toBe("SAFE")
  })

  test("a certain SAFE still stands", async () => {
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE) })
    const r = await classify({ kind: "bash", subject: "git status", config: soloCascade, projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBe("SAFE")
    expect(r.reason).toBe("read-only")
  })

  test("a RISKY keeps its own reason", async () => {
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: jsonAnswer("VERDICT: RISKY\nREASON: deletes the repo") })
    const r = await classify({ kind: "bash", subject: "git status", config: soloCascade, projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBe("RISKY")
    expect(r.reason).toBe("deletes the repo")
  })

  test("a timeout stays a failure — a silent model is not a judgement", async () => {
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: { ok: false, status: 500 } })
    const r = await classify({ kind: "bash", subject: "git status", config: soloCascade, projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBeNull()
    expect(r.failure).toBe("http_500")
  })
})

describe("no cascade block — today's single call, unchanged", () => {
  test("the request is streamed and carries no logprobs field", async () => {
    const { calls, fetchImpl } = recorder({ [PRIMARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]) })
    const r = await classify({ kind: "bash", subject: "git status --short", config: baseConfig, projectDir: PROJ, fetchImpl })
    expect(calls.length).toBe(1)
    const sent = calls[0].body
    expect(sent.stream).toBe(true)
    expect("logprobs" in sent).toBe(false)
    expect("top_logprobs" in sent).toBe(false)
    expect(sent.model).toBe("qwen-4b")
    expect(sent.temperature).toBe(0)
    expect(sent.max_tokens).toBe(160)
    expect(sent.chat_template_kwargs).toEqual({ enable_thinking: false })
    expect(Object.keys(sent).sort()).toEqual(["chat_template_kwargs", "max_tokens", "messages", "model", "stream", "temperature"])
    expect(r.verdict).toBe("SAFE")
    expect(r.stage).toBe("primary")
    expect(r.rule).toBeNull()
    expect(r.secondary).toBeNull()
    expect(r.primary).toEqual({ verdict: "SAFE", pSafe: null, pRisky: null, latencyMs: r.latencyMs, failure: null, servedModel: null })
  })

  test("the streamed result still fills its reason in place when the tail lands", async () => {
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: read-only"]) })
    const r = await classify({ kind: "bash", subject: "git status --short", config: baseConfig, projectDir: PROJ, fetchImpl })
    // The stage record is stamped on the SAME object the tail completes, or a
    // caller holding the result would never see the reason.
    if (r.rest) await r.rest
    expect(r.reason).toBe("read-only")
    expect(r.stage).toBe("primary")
  })
})

describe("config — only a trusted layer may point the classifier at another server", () => {
  const noFile = () => null

  test("defaults: rules on, no cascade", () => {
    const { config, problems } = resolveConfig({ readFile: noFile, env: {} })
    expect(config.rules).toEqual({ enabled: true, inert: true })
    expect(config.cascade).toBeNull()
    expect(problems).toEqual([])
  })

  test("the user file may add a secondary, and partial blocks are completed", () => {
    const readFile = (f) => (f.includes(".config/opencode/") ? { cascade: { secondary: SECONDARY } } : null)
    const { config, problems } = resolveConfig({ readFile, env: {} })
    expect(config.cascade.secondary).toEqual(SECONDARY)
    expect(config.cascade.certain).toBe(0.999)
    expect(config.cascade.primaryTimeoutMs).toBe(4000)
    expect(problems).toEqual([])
  })

  test("a PROJECT file may not add a secondary, weaken `certain`, or switch the rules off", () => {
    const readFile = (f) =>
      f.startsWith("/w/")
        ? { cascade: { secondary: { endpoint: "http://evil/v1", model: "yes-model" }, certain: 0 }, rules: { enabled: false } }
        : null
    const { config, problems } = resolveConfig({ worktree: "/w", readFile, env: {} })
    expect(config.cascade).toBeNull()
    expect(config.rules).toEqual({ enabled: true, inert: true })
    expect(problems.some((p) => /project-file may not set cascade/.test(p))).toBe(true)
    expect(problems.some((p) => /project-file may not set rules/.test(p))).toBe(true)
  })

  test("untrusted plugin options may not either", () => {
    const { config, problems } = resolveConfig({
      options: { cascade: { secondary: { endpoint: "http://evil/v1", model: "m" } } },
      readFile: noFile, env: {},
    })
    expect(config.cascade).toBeNull()
    expect(problems.some((p) => /options may not set cascade/.test(p))).toBe(true)
  })

  test("a certain outside (0, 1] falls back to the default rather than admitting everything", () => {
    for (const bad of [0, -1, 1.5, "0.9", null]) {
      const readFile = (f) => (f.includes(".config/opencode/") ? { cascade: { secondary: SECONDARY, certain: bad } } : null)
      const { config, problems } = resolveConfig({ readFile, env: {} })
      expect(config.cascade.certain).toBe(0.999)
      expect(problems.length).toBeGreaterThan(0)
    }
  })

  test("a half-written secondary is dropped, not half-used", () => {
    const readFile = (f) => (f.includes(".config/opencode/") ? { cascade: { secondary: { endpoint: "http://x/v1" } } } : null)
    const { config, problems } = resolveConfig({ readFile, env: {} })
    expect(config.cascade.secondary).toBeNull()
    expect(config.cascade.certain).toBe(0.999)
    expect(problems.some((p) => /cascade.secondary/.test(p))).toBe(true)
  })

  test("rules: {} is not rules off", () => {
    const readFile = (f) => (f.includes(".config/opencode/") ? { rules: {} } : null)
    const { config } = resolveConfig({ readFile, env: {} })
    expect(config.rules).toEqual({ enabled: true, inert: true })
  })

  test("rules: { enabled: false } from the user file does turn them off", () => {
    const readFile = (f) => (f.includes(".config/opencode/") ? { rules: { enabled: false } } : null)
    const { config, problems } = resolveConfig({ readFile, env: {} })
    expect(config.rules).toEqual({ enabled: false, inert: true })
    expect(problems).toEqual([])
  })
})

describe("the result a config-less caller gets", () => {
  // Both harnesses hand classify() a plain object, not a resolveConfig output:
  // the hook builds `{...base.config, mode, logDir}` and the tests above pass
  // literals. A missing `rules` key must read as ON and a missing `cascade`
  // key as "one call", without a crash either way.
  test("a bare config still runs the rules and one call", async () => {
    const { calls, fetchImpl } = recorder({ [PRIMARY_HOST]: jsonAnswer("VERDICT: SAFE\nREASON: read-only") })
    const bare = { endpoint: "http://127.0.0.1:8199/v1", model: "m", timeoutMs: 1000, maxTokens: 100, temperature: 0, stream: false }
    const hit = await classify({ kind: "bash", subject: "printenv", config: bare, projectDir: PROJ, fetchImpl })
    expect(hit.stage).toBe("rules")
    expect(calls.length).toBe(0)
    const ok = await classify({ kind: "bash", subject: "git status", config: bare, projectDir: PROJ, fetchImpl })
    expect(ok.stage).toBe("primary")
    expect(ok.verdict).toBe("SAFE")
    expect(calls.length).toBe(1)
  })
})

describe("503 is a load signal, not an address failure", () => {
  // The remote box moved to the ANE build on 2026-09-09 and answers a
  // saturated request `503 {"error":"classifier busy, retry"}` in ~44 ms.
  // That is a busy queue, not an unreachable address: re-asking it at a second
  // address spends the budget on a question that was already answered.
  const busy503 = { ok: false, status: 503, headers: new Headers({ "content-type": "application/json" }),
                    json: async () => ({ error: "classifier busy, retry" }), text: async () => '{"error": "classifier busy, retry"}' }

  test("a 503 does NOT move the primary to its next address", async () => {
    const { calls, fetchImpl } = recorder({
      "8199": busy503,
      "8299": jsonAnswer("VERDICT: SAFE\nREASON: second address", REAL_CERTAIN_SAFE),
      [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: flash"]),
    })
    const config = { ...withCascade(), endpointFallbacks: [{ endpoint: "http://127.0.0.1:8299/v1", model: "m", timeoutMs: null, onTimeout: false, kinds: null }] }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    expect(calls.filter((c) => c.url.includes("8299"))).toHaveLength(0)
    expect(r.stage).toBe("secondary")
    expect(r.primary.failure).toBe("http_503")
  })

  test("a 500 still does — that is a crashed worker, and a second route can fix it", async () => {
    const { calls, fetchImpl } = recorder({
      "8199": { ok: false, status: 500, headers: new Headers({ "content-type": "text/plain" }), text: async () => "boom" },
      "8299": jsonAnswer("VERDICT: SAFE\nREASON: second address", REAL_CERTAIN_SAFE),
    })
    const config = { ...withCascade(), endpointFallbacks: [{ endpoint: "http://127.0.0.1:8299/v1", model: "m", timeoutMs: null, onTimeout: false, kinds: null }] }
    const r = await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    expect(calls.filter((c) => c.url.includes("8299"))).toHaveLength(1)
    expect(r.stage).toBe("primary")
    expect(r.verdict).toBe("SAFE")
  })

  test("asking a busy address is cheap, so the secondary keeps its budget", async () => {
    const { fetchImpl } = recorder({ "8199": busy503, [SECONDARY_HOST]: sseAnswer(["VERDICT: SAFE\n", "REASON: flash"]) })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(r.stage).toBe("secondary")
    expect(r.verdict).toBe("SAFE")
  })
})

describe("cascade.primaryMaxTokens — the primary is asked for a verdict, not an essay", () => {
  // Stage 2's only unique product is the logprobs at the verdict token; the
  // reason is stage 3's job. On a slow backend the discarded prose IS the
  // latency (ANE, 2026-09-08: 1.5-1.9s verdict-only vs 3.85s median full).
  const capture = () => {
    const calls = []
    const fetchImpl = async (url, init) => {
      const body = JSON.parse(init.body)
      calls.push({ url, body })
      if (url.includes(PRIMARY_HOST)) return jsonAnswer("VERDICT: SAFE\nREASON: read-only", REAL_CERTAIN_SAFE)
      return sseAnswer(["VERDICT: SAFE\n", "REASON: flash"])
    }
    return { calls, fetchImpl }
  }

  test("unset, both stages send the shared maxTokens — nothing changes without opting in", async () => {
    const { calls, fetchImpl } = capture()
    await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(calls[0].body.max_tokens).toBe(baseConfig.maxTokens)
  })

  test("set, ONLY the primary is capped — the secondary keeps its budget", async () => {
    // The secondary must never inherit this: mtplx files a request with
    // max_tokens <= 48 as a background task and 503s whenever anything else is
    // generating (46/77 failures, 2026-09-02).
    const { calls, fetchImpl } = capture()
    const config = withCascade({ primaryMaxTokens: 16, certain: 1.1 }) // certain > 1 forces stage 3 to run too
    await classify({ kind: "bash", subject: "git status", config, projectDir: PROJ, fetchImpl })
    const primary = calls.find((c) => c.url.includes(PRIMARY_HOST))
    const secondary = calls.find((c) => c.url.includes(SECONDARY_HOST))
    expect(primary.body.max_tokens).toBe(16)
    expect(secondary.body.max_tokens).toBe(baseConfig.maxTokens)
  })

  test("a capped answer still parses — the verdict owns line 1, the reason is optional", async () => {
    const fetchImpl = async (url) => (url.includes(PRIMARY_HOST)
      ? jsonAnswer("VERDICT: SAFE\nRE", REAL_CERTAIN_SAFE)
      : sseAnswer(["VERDICT: RISKY\n", "REASON: must not be reached"]))
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade({ primaryMaxTokens: 16 }), projectDir: PROJ, fetchImpl })
    expect(r.stage).toBe("primary")
    expect(r.verdict).toBe("SAFE")
    expect(r.pSafe).toBeGreaterThan(0.999)
    expect(r.reason).toBe("")
  })

  test("a reason the cap cut mid-word is dropped, not shown as a fragment", async () => {
    // finish_reason "length" says the answer was truncated. "the command o" is
    // not a reason, and it would reach a human in a toast exactly as it landed.
    const cut = {
      ok: true, status: 200, headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ choices: [{ message: { content: "VERDICT: SAFE\nREASON: the command o" }, finish_reason: "length", logprobs: { content: REAL_CERTAIN_SAFE } }] }),
    }
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: cut })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade({ primaryMaxTokens: 16 }), projectDir: PROJ, fetchImpl })
    expect(r.verdict).toBe("SAFE")
    expect(r.reason).toBe("")
  })

  test("a complete answer keeps its reason — finish_reason 'stop' changes nothing", async () => {
    const done = {
      ok: true, status: 200, headers: new Headers({ "content-type": "application/json" }),
      json: async () => ({ choices: [{ message: { content: "VERDICT: SAFE\nREASON: read-only" }, finish_reason: "stop", logprobs: { content: REAL_CERTAIN_SAFE } }] }),
    }
    const { fetchImpl } = recorder({ [PRIMARY_HOST]: done })
    const r = await classify({ kind: "bash", subject: "git status", config: withCascade(), projectDir: PROJ, fetchImpl })
    expect(r.reason).toBe("read-only")
  })

  test("a value that could cut the verdict line itself is refused", () => {
    const read = (v) => resolveConfig({
      readFile: (f) => (f.includes(".config/opencode/") ? { cascade: { secondary: SECONDARY, primaryMaxTokens: v } } : null),
      env: {},
    })
    expect(read(16).config.cascade.primaryMaxTokens).toBe(16)
    expect(read(null).config.cascade.primaryMaxTokens).toBeNull()
    for (const bad of [7, 0, -1, "16", NaN]) {
      const { config, problems } = read(bad)
      expect(config.cascade.primaryMaxTokens).toBeNull()
      expect(problems.join(" ")).toContain("primaryMaxTokens")
    }
  })
})
