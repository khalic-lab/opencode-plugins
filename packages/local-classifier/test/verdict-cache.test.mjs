/**
 * The verdict cache, and the order it sits in.
 *
 * WHAT IT IS FOR. Over the 2026-09-02..09 shadow window the classifier judged
 * 7,121 commands containing 6,674 distinct subjects, so an exact-match cache
 * cannot answer more than ~6% of traffic however long the TTL. It is kept
 * because of where that 6% is removed FROM — a single-tenant serial model
 * server this classifier saturates by itself — and because no looser key is
 * available: every normalization that manufactures reuse erases the operand
 * that decides risk (replacing paths with a placeholder reaches 24% reuse and
 * puts `rm -rf /tmp/build` and `rm -rf /` on one key).
 *
 * WHAT THE TESTS ARE FOR. Almost none of the risk is in the hit rate; it is in
 * the ORDER. A cached verdict that could answer ahead of the rules would let a
 * five-minute-old SAFE speak for a filesystem that has changed since, and the
 * rules are the part of this classifier that reads the filesystem. That
 * property gets the first describe block and the most tests.
 */
import { describe, test, expect } from "bun:test"
import { LocalClassifier } from "../local-classifier.js"

const {
  preflight, classify, cacheKey, createMemoryCache, cacheableResult,
  resolveConfig, SUBJECT_CACHE_MAX,
} = LocalClassifier.internals

const PROJ = "/usr/local/src/webapp-142"
const config = (over = {}) => ({ ...resolveConfig({ readFile: () => null, env: {} }).config, ...over })

/** A cache that records every call, so "was it consulted?" is assertable. */
const spyCache = (inner = createMemoryCache()) => {
  const gets = []
  const puts = []
  return {
    gets, puts,
    get(k) { gets.push(k); return inner.get(k) },
    put(k, v) { puts.push(k); return inner.put(k, v) },
    seed(kind, subject, result) { inner.put(cacheKey(kind, subject), result) },
  }
}

const mustNotFetch = async () => { throw new Error("the model must not be called") }

describe("the cache is consulted LAST, after both rule layers", () => {
  test("a RISKY rule beats a cached SAFE for the same command", () => {
    // The failure this pins: a cache in front of the rules. The rules are what
    // `stat` the filesystem — destination-exists, truncate-existing,
    // scratch-execution — so a verdict cached before a tree changed must never
    // be allowed to answer for it afterwards.
    const cache = spyCache()
    const subject = "git push --force-with-lease origin main"
    cache.seed("bash", subject, { verdict: "SAFE", reason: "cached and wrong" })

    const r = preflight({ kind: "bash", subject, config: config(), projectDir: PROJ, cache })
    expect(r.verdict).toBe("RISKY")
    expect(r.rule).toBe("force-push")
    expect(r.cached).toBeUndefined()
    expect(cache.gets).toEqual([]) // never even asked
  })

  test("an inert-reader SAFE beats a cached RISKY, for the same reason", () => {
    const cache = spyCache()
    cache.seed("bash", "cat README.md", { verdict: "RISKY", reason: "cached and wrong" })

    const r = preflight({ kind: "bash", subject: "cat README.md", config: config(), projectDir: PROJ, cache })
    expect(r.verdict).toBe("SAFE")
    expect(r.rule).toBe("inert-readers")
    expect(cache.gets).toEqual([])
  })

  test("only what the rules decline reaches the cache", () => {
    const cache = spyCache()
    const subject = "git status"
    cache.seed("bash", subject, { verdict: "SAFE", reason: "a real earlier verdict" })

    const r = preflight({ kind: "bash", subject, config: config(), projectDir: PROJ, cache })
    expect(r.verdict).toBe("SAFE")
    expect(r.cached).toBe(true)
    expect(cache.gets).toEqual([cacheKey("bash", subject)])
  })

  test("nothing decided locally means null, and the caller pays for a model", () => {
    const cache = spyCache()
    expect(preflight({ kind: "bash", subject: "git status", config: config(), projectDir: PROJ, cache })).toBeNull()
  })

  test("no cache at all is a supported shape, not a crash", () => {
    expect(preflight({ kind: "bash", subject: "git status", config: config(), projectDir: PROJ })).toBeNull()
    expect(preflight({ kind: "bash", subject: "cat f", config: config(), projectDir: PROJ })?.verdict).toBe("SAFE")
  })
})

describe("what goes in, and what deliberately does not", () => {
  test("a rules verdict is never stored — it is cheaper to re-derive than to trust", async () => {
    const cache = spyCache()
    await classify({ kind: "bash", subject: "cat README.md", config: config(), projectDir: PROJ, cache, fetchImpl: mustNotFetch })
    expect(cache.puts).toEqual([])
  })

  test("a model verdict is stored, and answers the next identical call", async () => {
    let asked = 0
    const fetchImpl = async () => {
      asked += 1
      return {
        ok: true, status: 200,
        headers: new Headers({ "content-type": "application/json" }),
        json: async () => ({ choices: [{ message: { content: "VERDICT: SAFE\nREASON: ok" } }] }),
      }
    }
    const cache = createMemoryCache()
    const cfg = config({ stream: false, timeoutMs: 1000 })
    const args = { kind: "bash", subject: "git status", config: cfg, projectDir: PROJ, cache, fetchImpl }

    const first = await classify(args)
    expect(asked).toBe(1)
    expect(first.cached).toBeUndefined()

    const second = await classify(args)
    expect(asked).toBe(1) // the model was not asked again
    expect(second.verdict).toBe("SAFE")
    expect(second.cached).toBe(true)
  })

  test("a failure is never stored — a timeout is not a verdict", async () => {
    const cache = spyCache()
    const fetchImpl = async () => { throw new Error("ECONNREFUSED") }
    const r = await classify({ kind: "bash", subject: "git status", config: config({ timeoutMs: 200 }), projectDir: PROJ, cache, fetchImpl })
    expect(r.failure).toBeTruthy()
    expect(cache.puts).toEqual([])
  })

  test("the stored shape drops everything that belonged to the call that made it", () => {
    // `rest` is a promise the next caller must never await; `raw` is the
    // completion text, 4 kB that no cached row prints; the latencies describe
    // a call that already happened.
    const stored = cacheableResult({
      verdict: "RISKY", reason: "deletes a tracked path", raw: "VERDICT: RISKY\nREASON: …",
      rest: Promise.resolve({ reason: "late" }), latencyMs: 1234, cascadeMs: 5678,
      failure: null, pSafe: 0.02, pRisky: 0.98, stage: "secondary", rule: null,
    })
    expect(stored.rest).toBeNull()
    expect(stored.raw).toBeNull()
    expect(stored.latencyMs).toBeNull()
    expect(stored.cascadeMs).toBeNull()
    expect(stored.reason).toBe("deletes a tracked path")
    expect(stored.pRisky).toBe(0.98)
    expect(stored.stage).toBe("secondary")
  })

  test("a cached RISKY carries its whole reason and no promise to await", () => {
    const cache = spyCache()
    cache.seed("bash", "some cmd", { verdict: "RISKY", reason: "whole reason", rest: Promise.resolve({ reason: "x" }) })
    const r = preflight({ kind: "bash", subject: "some cmd", config: config(), projectDir: PROJ, cache })
    expect(r.rest).toBeNull()
    expect(r.reason).toBe("whole reason")
  })
})

describe("the key, the clock and the bound", () => {
  test("kind is part of the key — the same text is a different question", () => {
    expect(cacheKey("bash", "/tmp/x")).not.toBe(cacheKey("external_directory", "/tmp/x"))
  })

  test("an entry expires on the TTL, and expiry drops it rather than hiding it", () => {
    let t = 1_000_000
    const cache = createMemoryCache({ ttlMs: 5_000, now: () => t })
    cache.put("k", { verdict: "SAFE" })
    t += 4_999
    expect(cache.get("k")?.verdict).toBe("SAFE")
    t += 2
    expect(cache.get("k")).toBeNull()
    expect(cache.size()).toBe(0)
  })

  test("the map is bounded, oldest out", () => {
    const cache = createMemoryCache({ max: 3 })
    for (const k of ["a", "b", "c", "d"]) cache.put(k, { verdict: "SAFE" })
    expect(cache.size()).toBe(3)
    expect(cache.get("a")).toBeNull()
    expect(cache.get("d")?.verdict).toBe("SAFE")
  })

  test("the shipped bound is a number, not an accident", () => {
    expect(SUBJECT_CACHE_MAX).toBe(200)
    expect(createMemoryCache().size()).toBe(0)
  })
})
