// Unit tests for the hook's pure parts: the busy probe, the file-backed
// breaker's backoff, and the decision table. The exit-discipline battery
// covers the process-level contract against the real model; this file covers
// what can be checked without one.
import { describe, test, expect } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"

process.env.CC_CLASSIFIER_LIBRARY = "1"
const { hookInternals: H } = await import("../cc-classifier-hook.mjs")
const { LocalClassifier } = await import("../../local-classifier/local-classifier.js")

const cfg = (over = {}) => ({ ...H.HOOK_DEFAULTS, ...over })

describe("probeBusy", () => {
  const fakeFetch = (active, { ok = true, throws = false } = {}) => {
    const fn = async (url, opts) => {
      fn.lastUrl = url
      fn.lastOpts = opts
      if (throws) throw new Error("connect ECONNREFUSED")
      return { ok, json: async () => ({ enabled: true, active, recent: [] }) }
    }
    return fn
  }

  test("a long in-flight request is busy; the longest one is reported", async () => {
    const f = fakeFetch([
      { rid: "a", prompt_tokens: 7000, phase: "decode", elapsed_s: 2.5 },
      { rid: "b", prompt_tokens: 52000, phase: "prefill", elapsed_s: 3.1 },
    ])
    const { busy, probe } = await H.probeBusy({ endpoint: "http://127.0.0.1:7777/proxy/m/v1/" }, cfg(), f)
    expect(busy).toEqual({ prompt_tokens: 52000, phase: "prefill", elapsed_s: 3.1, active: 2 })
    expect(probe).toBe("busy")
    expect(f.lastUrl).toBe("http://127.0.0.1:7777/proxy/m/v1/mtplx/flight")
    expect(f.lastOpts.signal).toBeInstanceOf(AbortSignal)
  })
  test("short requests in flight are not busy", async () => {
    const f = fakeFetch([{ rid: "a", prompt_tokens: 2400, phase: "decode", elapsed_s: 0.4 }])
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), f)).toEqual({ busy: null, probe: "free" })
  })
  test("nothing in flight is not busy", async () => {
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), fakeFetch([]))).toEqual({ busy: null, probe: "free" })
  })
  test("the threshold is the config's", async () => {
    const f = fakeFetch([{ prompt_tokens: 7000 }])
    expect((await H.probeBusy({ endpoint: "http://x/v1" }, cfg({ busyPromptTokens: 6500 }), f)).busy).toMatchObject({ prompt_tokens: 7000 })
    expect((await H.probeBusy({ endpoint: "http://x/v1" }, cfg({ busyPromptTokens: 7001 }), f)).busy).toBeNull()
  })
  test("with a cascade, the probe follows the SECONDARY's server", async () => {
    // The primary is a single-tenant mlx_lm.server with no flight list; the
    // secondary is the mtplx endpoint the probe was written for.
    const f = fakeFetch([{ prompt_tokens: 52000, phase: "prefill", elapsed_s: 3.1 }])
    const classifier = {
      endpoint: "http://127.0.0.1:8199/v1",
      cascade: { secondary: { endpoint: "http://127.0.0.1:7777/proxy/flash/v1", model: "flash-next" } },
    }
    const { busy, probe } = await H.probeBusy(classifier, cfg(), f)
    expect(f.lastUrl).toBe("http://127.0.0.1:7777/proxy/flash/v1/mtplx/flight")
    expect(probe).toBe("busy")
    expect(busy).toMatchObject({ prompt_tokens: 52000 })
  })
  test("a cascade with no secondary probes the primary, as before", async () => {
    const f = fakeFetch([])
    await H.probeBusy({ endpoint: "http://127.0.0.1:8199/v1", cascade: { secondary: null } }, cfg(), f)
    expect(f.lastUrl).toBe("http://127.0.0.1:8199/v1/mtplx/flight")
  })
  test("0 disables the probe without a request", async () => {
    let called = false
    const f = async () => { called = true; return { ok: true, json: async () => ({ active: [{ prompt_tokens: 99999 }] }) } }
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg({ busyPromptTokens: 0 }), f)).toEqual({ busy: null, probe: "off" })
    expect(called).toBe(false)
  })
  test("a failing, missing or malformed endpoint is never busy, and says why", async () => {
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), fakeFetch([], { throws: true }))).toEqual({ busy: null, probe: "unavailable:Error" })
    const notFound = async () => ({ ok: false, status: 404 })
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), notFound)).toEqual({ busy: null, probe: "unavailable:http_404" })
    const junk = async () => ({ ok: true, json: async () => "not an object" })
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), junk)).toEqual({ busy: null, probe: "unavailable:no_active_list" })
    const noActive = async () => ({ ok: true, json: async () => ({ active: "nope" }) })
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), noActive)).toEqual({ busy: null, probe: "unavailable:no_active_list" })
  })
  test("a probe that hangs is abandoned inside busyProbeMs", async () => {
    const hang = (url, { signal }) => new Promise((_, reject) => { signal.addEventListener("abort", () => reject(signal.reason)) })
    const t = Date.now()
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg({ busyProbeMs: 50 }), hang)).toEqual({ busy: null, probe: "unavailable:timeout" })
    expect(Date.now() - t).toBeLessThan(1000)
  })
})

describe("loadBreaker — file-backed, with backoff", () => {
  const fresh = () => fs.mkdtempSync(path.join(os.tmpdir(), "cc-breaker-"))
  const c = (dir, over = {}) => cfg({ stateDir: dir, breakerThreshold: 3, breakerCooldownMs: 1000, breakerMaxCooldownMs: 4000, ...over })

  test("opens after `threshold` consecutive failures, closes after the cooldown", () => {
    const dir = fresh()
    let t = 1_000_000
    const now = () => t
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
    H.loadBreaker(c(dir), now).record(true)
    H.loadBreaker(c(dir), now).record(true)
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
    const third = H.loadBreaker(c(dir), now).record(true)
    expect(third).toEqual({ consecutiveFailures: 3, openedAt: t, opens: 1 })
    expect(H.loadBreaker(c(dir), now).open).toBe(true)
    expect(H.loadBreaker(c(dir), now).state.cooldownMs).toBe(1000)
    t += 999
    expect(H.loadBreaker(c(dir), now).open).toBe(true)
    t += 1
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
  })
  test("each re-open without a success doubles the cooldown, up to the cap", () => {
    const dir = fresh()
    let t = 1_000_000
    const now = () => t
    for (let i = 0; i < 3; i++) H.loadBreaker(c(dir), now).record(true)
    expect(H.loadBreaker(c(dir), now).state).toMatchObject({ opens: 1, cooldownMs: 1000 })
    t += 1000 // cooldown over, the next call is the probe — and it fails
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
    expect(H.loadBreaker(c(dir), now).record(true)).toMatchObject({ opens: 2, openedAt: t })
    expect(H.loadBreaker(c(dir), now).state.cooldownMs).toBe(2000)
    t += 1500
    expect(H.loadBreaker(c(dir), now).open).toBe(true) // 1.5 s into a 2 s cooldown
    t += 500
    H.loadBreaker(c(dir), now).record(true)
    expect(H.loadBreaker(c(dir), now).state).toMatchObject({ opens: 3, cooldownMs: 4000 })
    t += 4000
    H.loadBreaker(c(dir), now).record(true)
    expect(H.loadBreaker(c(dir), now).state).toMatchObject({ opens: 4, cooldownMs: 4000 }) // capped
  })
  test("one success resets failures, opens and cooldown", () => {
    const dir = fresh()
    let t = 1_000_000
    const now = () => t
    for (let i = 0; i < 5; i++) { H.loadBreaker(c(dir), now).record(true); t += 5000 }
    expect(H.loadBreaker(c(dir), now).state.opens).toBeGreaterThan(1)
    expect(H.loadBreaker(c(dir), now).record(false)).toEqual({ consecutiveFailures: 0, openedAt: 0, opens: 0 })
    expect(H.loadBreaker(c(dir), now).state.cooldownMs).toBe(1000)
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
  })
  test("a success while open closes it at once (what the warm relies on)", () => {
    const dir = fresh()
    let t = 1_000_000
    const now = () => t
    for (let i = 0; i < 3; i++) H.loadBreaker(c(dir), now).record(true)
    t += 100
    expect(H.loadBreaker(c(dir), now).open).toBe(true)
    H.loadBreaker(c(dir), now).record(false)
    expect(H.loadBreaker(c(dir), now).open).toBe(false)
  })
  test("a future openedAt, a pre-backoff state file, or junk counts as closed", () => {
    const dir = fresh()
    const file = path.join(dir, "breaker.json")
    fs.writeFileSync(file, JSON.stringify({ consecutiveFailures: 3, openedAt: Date.now() + 10_000_000 }))
    expect(H.loadBreaker(c(dir)).open).toBe(false)
    // 0.3.0 wrote no `opens`; that state must read as one open, cooldown = base.
    fs.writeFileSync(file, JSON.stringify({ consecutiveFailures: 3, openedAt: Date.now() - 10 }))
    expect(H.loadBreaker(c(dir))).toMatchObject({ open: true, state: { opens: 0, cooldownMs: 1000 } })
    fs.writeFileSync(file, "{not json")
    expect(H.loadBreaker(c(dir)).open).toBe(false)
    fs.writeFileSync(file, JSON.stringify({ consecutiveFailures: "many", openedAt: "yesterday", opens: -4 }))
    expect(H.loadBreaker(c(dir)).open).toBe(false)
  })
  test("cooldownFor is the schedule", () => {
    const k = c("/nowhere")
    expect([0, 1, 2, 3, 4, 9].map((n) => H.cooldownFor(k, n))).toEqual([1000, 1000, 2000, 4000, 4000, 4000])
  })
})

describe("planFor — the posture table as a function", () => {
  const p = (posture, over = {}) => ({ posture, breakerPolicy: "deny", ...over })
  test("verdicts follow the posture", () => {
    expect(H.planFor({ verdict: "SAFE" }, p("cascade"))).toMatchObject({ outcome: "allow", why: "classified SAFE" })
    expect(H.planFor({ verdict: "SAFE" }, p("veto"))).toMatchObject({ outcome: "pass" })
    expect(H.planFor({ verdict: "RISKY", reason: "deletes src" }, p("cascade"))).toMatchObject({ outcome: "pass", why: "classified RISKY: deletes src — left to the built-in classifier" })
    expect(H.planFor({ verdict: "RISKY", reason: "deletes src" }, p("veto"))).toMatchObject({ outcome: "deny", why: "classified RISKY: deletes src" })
    expect(H.planFor({ verdict: "RISKY", reason: "x" }, p("solo"), "path outside the project classified RISKY").why).toBe("path outside the project classified RISKY: x")
  })
  test("busy is a known-unavailable failure: cascade passes, veto denies unless the breaker policy allows", () => {
    const busy = { verdict: null, failure: "busy", busy: { prompt_tokens: 52000, phase: "prefill", elapsed_s: 3, active: 1 } }
    expect(H.planFor(busy, p("cascade"))).toMatchObject({
      outcome: "pass", why: "classifier busy (a 52000-token request is in flight) — left to the built-in classifier",
      extra: { verdict: null, failure: "busy", busy: busy.busy },
    })
    expect(H.planFor(busy, p("veto"))).toMatchObject({ outcome: "deny" })
    expect(H.planFor(busy, p("veto", { breakerPolicy: "allow" }))).toMatchObject({ outcome: "pass", why: expect.stringContaining("degraded") })
    expect(H.planFor({ verdict: null, failure: "breaker_open" }, p("solo", { breakerPolicy: "allow" }))).toMatchObject({ outcome: "pass" })
  })
  test("an ordinary failure denies under veto and solo whatever the breaker policy", () => {
    expect(H.planFor({ verdict: null, failure: "timeout" }, p("veto", { breakerPolicy: "allow" }))).toMatchObject({ outcome: "deny", why: "classifier failed (timeout)" })
    expect(H.planFor({ verdict: null, failure: "timeout" }, p("cascade"))).toMatchObject({ outcome: "pass" })
  })
})

describe("resolveHookConfig — the new keys", () => {
  const I = LocalClassifier.internals
  const env = (over = {}) => ({ HOME: fs.mkdtempSync(path.join(os.tmpdir(), "cc-home-")), ...over })
  test("defaults", () => {
    const { hook } = H.resolveHookConfig(I, env())
    expect(hook).toMatchObject({ busyPromptTokens: 6000, busyProbeMs: 400, breakerMaxCooldownMs: 300_000, shadowDetached: true })
  })
  test("env overrides for the battery", () => {
    const { hook } = H.resolveHookConfig(I, env({ CC_CLASSIFIER_SHADOW_DETACHED: "0", CC_CLASSIFIER_BUSY_PROMPT_TOKENS: "0" }))
    expect(hook).toMatchObject({ shadowDetached: false, busyPromptTokens: 0 })
  })
  test("junk degrades to the default and is reported, never thrown", () => {
    const { hook, problems } = H.resolveHookConfig(I, env({ CC_CLASSIFIER_BUSY_PROMPT_TOKENS: "lots" }))
    expect(hook.busyPromptTokens).toBe(6000)
    expect(problems.some((p) => p.includes("busyPromptTokens"))).toBe(true)
  })
  test("a threshold under the classifier's own request size is refused (it would read a sibling hook as busy)", () => {
    const { hook, problems } = H.resolveHookConfig(I, env({ CC_CLASSIFIER_BUSY_PROMPT_TOKENS: "2000" }))
    expect(hook.busyPromptTokens).toBe(6000)
    expect(problems.some((p) => p.includes("at least 5000"))).toBe(true)
    expect(H.resolveHookConfig(I, env({ CC_CLASSIFIER_BUSY_PROMPT_TOKENS: "5000" })).hook.busyPromptTokens).toBe(5000)
  })
})
