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
    // `inFlight` rides on every probe result, busy or not: the depth is only
    // useful if it is recorded for the calls that RAN.
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), f)).toEqual({ busy: null, probe: "free", inFlight: 1 })
  })
  test("nothing in flight is not busy", async () => {
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), fakeFetch([]))).toEqual({ busy: null, probe: "free", inFlight: 0 })
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
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg(), fakeFetch([], { throws: true }))).toEqual({ busy: null, probe: "unavailable:Error", inFlight: null })
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
    expect(await H.probeBusy({ endpoint: "http://x/v1" }, cfg({ busyProbeMs: 50 }), hang)).toEqual({ busy: null, probe: "unavailable:timeout", inFlight: null })
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
  test("no_api_key is booked as nothing: neither opens nor closes the shared breaker", () => {
    const dir = fresh()
    const now = () => 1_000_000
    H.loadBreaker(c(dir), now).record(true)
    H.loadBreaker(c(dir), now).record(true)
    for (let i = 0; i < 5; i++) {
      expect(H.recordOutcome(H.loadBreaker(c(dir), now), { failure: "no_api_key" }).openedAt).toBe(0)
    }
    expect(H.loadBreaker(c(dir), now).state.consecutiveFailures).toBe(2) // not reset, not advanced
    expect(H.recordOutcome(H.loadBreaker(c(dir), now), { failure: "timeout" }).openedAt).toBe(1_000_000)
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

describe("extraRoots", () => {
  const home = os.homedir()

  test("absolute roots survive and ~ is expanded", () => {
    const problems = []
    const out = H.normalizeExtraRoots(["/usr/local/src/khalic-lab/x", "~/code/y"], problems)
    expect(out).toEqual(["/usr/local/src/khalic-lab/x", path.join(home, "code/y")])
    expect(problems).toEqual([])
  })

  // A root at or above HOME, or a system directory, would switch the boundary
  // rule off for most of the disk. Rejected outright, never clamped.
  test("over-broad roots are rejected and reported", () => {
    for (const bad of ["/", home, "~", "/etc", "/usr", path.dirname(home)]) {
      const problems = []
      expect(H.normalizeExtraRoots([bad], problems)).toEqual([])
      expect(problems.length).toBe(1)
    }
  })

  test("bad entries drop individually; a non-array is refused whole", () => {
    const problems = []
    expect(H.normalizeExtraRoots(["/tmp/ok", "", 7, null], problems)).toEqual(["/tmp/ok"])
    expect(problems.length).toBe(3)
    expect(H.normalizeExtraRoots("/tmp/nope", [])).toEqual([])
    expect(H.normalizeExtraRoots(undefined, [])).toEqual([])
  })

  test("ccOwnRoot returns a declared root, and prefers it over the built-ins", () => {
    const root = "/usr/local/src/spike"
    expect(H.ccOwnRoot(`${root}/packages/a.js`, [root])).toBe(root)
    expect(H.ccOwnRoot(`${root}/packages/a.js`, [])).toBeNull()
    expect(H.ccOwnRoot("/usr/local/src/spike-other/a.js", [root])).toBeNull()
  })

  test("the built-in roots still work with no extras declared", () => {
    const uid = process.getuid()
    expect(H.ccOwnRoot(`/tmp/claude-${uid}/x/y.txt`)).toBe(`/tmp/claude-${uid}`)
    expect(H.ccOwnRoot(path.join(home, ".claude", "plans", "p.md"))).toBe(path.join(home, ".claude", "plans"))
  })

  test("a declared root does not disable the sensitive-path rules inside it", () => {
    const I = LocalClassifier.internals
    const root = "/tmp/declared"
    expect(I.judgeWritePath(`${root}/.ssh/id_rsa`, root)).not.toBeNull()
    expect(I.judgeWritePath(`${root}/src/app.js`, root)).toBeNull()
  })
})

describe("ask-then-remember", () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "cc-ask-"))
  const cfgAsk = (over = {}) => cfg({
    stateDir: path.join(tmp, "state"),
    rememberedRootsFile: path.join(tmp, "state", "remembered-roots.json"),
    outsideProjectAction: "ask",
    ...over,
  })

  test("candidateRootFor prefers the enclosing git repo over the file's folder", () => {
    const repo = path.join(tmp, "repo")
    fs.mkdirSync(path.join(repo, "a", "b"), { recursive: true })
    fs.mkdirSync(path.join(repo, ".git"), { recursive: true })
    expect(H.candidateRootFor(path.join(repo, "a", "b", "f.txt"))).toBe(repo)

    const loose = path.join(tmp, "loose", "deep")
    fs.mkdirSync(loose, { recursive: true })
    expect(H.candidateRootFor(path.join(loose, "f.txt"))).toBe(loose)
  })

  // The whole point of the park/claim pair: only a folder the user was actually
  // asked about, on a call that actually ran, gets remembered.
  test("a parked ask is claimed exactly once, by its own tool_use_id", () => {
    const c = cfgAsk()
    H.parkAsk(c, "call-1", "/tmp/root-one")
    expect(H.claimAsk(c, "call-2")).toBeNull()
    expect(H.claimAsk(c, "call-1")).toBe("/tmp/root-one")
    expect(H.claimAsk(c, "call-1")).toBeNull()
  })

  test("an ask nobody approved is never collected", () => {
    const c = cfgAsk()
    H.parkAsk(c, "declined", "/tmp/never")
    expect(H.loadRememberedRoots(c)).not.toContain("/tmp/never")
  })

  test("remembering is idempotent and readable back", () => {
    const c = cfgAsk({ rememberedRootsFile: path.join(tmp, "state", "r2.json") })
    expect(H.rememberRoot(c, "/tmp/remembered").added).toBe(true)
    expect(H.rememberRoot(c, "/tmp/remembered").added).toBe(false)
    expect(H.loadRememberedRoots(c)).toEqual(["/tmp/remembered"])
  })

  test("a remembered root still cannot be over-broad", () => {
    const c = cfgAsk({ rememberedRootsFile: path.join(tmp, "state", "r3.json") })
    fs.mkdirSync(path.dirname(c.rememberedRootsFile), { recursive: true })
    fs.writeFileSync(c.rememberedRootsFile, JSON.stringify({ roots: [os.homedir(), "/", "/tmp/fine"] }))
    expect(H.loadRememberedRoots(c)).toEqual(["/tmp/fine"])
  })

  test("outsideProjectAction only accepts deny or ask", () => {
    expect(H.HOOK_DEFAULTS.outsideProjectAction).toBe("deny")
  })
})

describe("the file-backed verdict cache", () => {
  const I = LocalClassifier.internals
  const freshCfg = () => cfg({ stateDir: fs.mkdtempSync(path.join(os.tmpdir(), "cc-vcache-")) })

  test("a verdict written by one process is read by the next", () => {
    // The whole reason this is on disk. The plugin holds the identical shape
    // in a closure because it is one long-lived process; a hook is a fresh
    // process per tool call, so an in-process Map would never see a hit.
    const c = freshCfg()
    const writer = H.loadVerdictCache(c, I)
    writer.put(I.cacheKey("bash", "git status"), { verdict: "SAFE", reason: "ok" })

    const reader = H.loadVerdictCache(c, I)
    expect(reader.get(I.cacheKey("bash", "git status"))).toMatchObject({ verdict: "SAFE", reason: "ok" })
    expect(reader.get(I.cacheKey("bash", "git diff"))).toBeNull()
    expect(reader.get(I.cacheKey("external_directory", "git status"))).toBeNull()
  })

  test("the file holds hashes, never command text", () => {
    // The log already keeps command text under the user's own policy. A cache
    // is state; a second copy of every command in another place with another
    // lifetime is not something to create as a side effect.
    const c = freshCfg()
    const cache = H.loadVerdictCache(c, I)
    cache.put(I.cacheKey("bash", "curl https://api.example.com -H 'Authorization: Bearer sk-live-42'"), { verdict: "SAFE" })

    const raw = fs.readFileSync(cache.file, "utf8")
    expect(raw).not.toContain("sk-live-42")
    expect(raw).not.toContain("curl")
    expect(Object.keys(JSON.parse(raw).entries)[0]).toMatch(/^[0-9a-f]{16}$/)
  })

  test("the stored value is the reduced shape, not the whole result", () => {
    const c = freshCfg()
    const cache = H.loadVerdictCache(c, I)
    cache.put(I.cacheKey("bash", "x"), {
      verdict: "SAFE", reason: "ok", raw: "VERDICT: SAFE\nREASON: ok",
      latencyMs: 900, cascadeMs: 900, rest: null, stage: "primary",
    })
    const got = cache.get(I.cacheKey("bash", "x"))
    expect(got.raw).toBeNull()
    expect(got.latencyMs).toBeNull()
    expect(got.stage).toBe("primary")
  })

  test("an entry past the TTL is not returned", () => {
    const c = freshCfg()
    let t = 1_000_000
    const cache = H.loadVerdictCache(c, I, () => t)
    cache.put(I.cacheKey("bash", "x"), { verdict: "SAFE" })
    expect(cache.get(I.cacheKey("bash", "x"))).not.toBeNull()
    t += I.SUBJECT_CACHE_TTL_MS + 1
    expect(cache.get(I.cacheKey("bash", "x"))).toBeNull()
  })

  test("the file is bounded, newest kept", () => {
    const c = freshCfg()
    let t = 1_000_000
    const cache = H.loadVerdictCache(c, I, () => t)
    for (let i = 0; i < I.SUBJECT_CACHE_MAX + 10; i++) {
      t += 1
      cache.put(I.cacheKey("bash", `cmd ${i}`), { verdict: "SAFE" })
    }
    expect(Object.keys(JSON.parse(fs.readFileSync(cache.file, "utf8")).entries)).toHaveLength(I.SUBJECT_CACHE_MAX)
    expect(cache.get(I.cacheKey("bash", "cmd 0"))).toBeNull()
    expect(cache.get(I.cacheKey("bash", `cmd ${I.SUBJECT_CACHE_MAX + 9}`))).not.toBeNull()
  })

  test("a corrupt, foreign or missing file reads as empty and never throws", () => {
    // Same policy as the breaker: a cache that cannot remember is the status
    // quo, and that must never be a reason to block a tool call or crash.
    const c = freshCfg()
    const cache = H.loadVerdictCache(c, I)
    expect(cache.get(I.cacheKey("bash", "x"))).toBeNull() // no file yet

    fs.mkdirSync(c.stateDir, { recursive: true })
    for (const body of ["{not json", "[]", '{"schema":99,"entries":{"a":1}}', '{"entries":null}']) {
      fs.writeFileSync(cache.file, body)
      expect(cache.get(I.cacheKey("bash", "x"))).toBeNull()
    }
    // ...and a put over a corrupt file repairs it rather than propagating.
    fs.writeFileSync(cache.file, "{not json")
    cache.put(I.cacheKey("bash", "x"), { verdict: "SAFE" })
    expect(cache.get(I.cacheKey("bash", "x"))?.verdict).toBe("SAFE")
  })

  test("an unwritable state dir is survivable", () => {
    const cache = H.loadVerdictCache(cfg({ stateDir: "/proc/nonexistent/nope" }), I)
    expect(() => cache.put(I.cacheKey("bash", "x"), { verdict: "SAFE" })).not.toThrow()
    expect(cache.get(I.cacheKey("bash", "x"))).toBeNull()
  })
})
