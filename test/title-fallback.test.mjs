import { describe, test, expect } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { TitleFallback } from "../plugin/title-fallback.js"

// Constructing the plugin writes a `plugin.init` line. Without this the suite
// would append to the real log dir the deployed plugin uses, which is also the
// place we read when asking whether a live session was repaired.
process.env.OPENCODE_TITLE_FALLBACK_LOG_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "title-fallback-test-"))

const { DEFAULT_TITLE, DEFAULTS, capTitle, generateTitle, sliceTitle, userText } = TitleFallback.internals

describe("DEFAULT_TITLE — opencode's own isDefaultTitle, transcribed", () => {
  test("matches the title opencode leaves when generation fails", () => {
    expect(DEFAULT_TITLE.test("New session - 2026-08-23T00:32:58.489Z")).toBe(true)
  })

  test("rejects a child session — ensureTitle skips those and so must we", () => {
    expect(DEFAULT_TITLE.test("Child session - 2026-08-23T00:32:58.489Z")).toBe(false)
  })

  test("rejects a real title, including one that merely starts the same way", () => {
    expect(DEFAULT_TITLE.test("Vite 6 build broken: Rollup missing export")).toBe(false)
    expect(DEFAULT_TITLE.test("New session - notes")).toBe(false)
  })
})

describe("capTitle", () => {
  test("keeps the first non-empty line and drops the rest", () => {
    expect(capTitle("\n\nApp.js failure investigation\nbecause the import is missing")).toBe(
      "App.js failure investigation",
    )
  })

  test("strips a reasoning block before looking for the line", () => {
    expect(capTitle("<think>the user wants a title</think>\nRate limiting implementation")).toBe(
      "Rate limiting implementation",
    )
  })

  test("unwraps quotes a small model likes to add", () => {
    expect(capTitle('"Postgres API connection"')).toBe("Postgres API connection")
  })

  test("caps at opencode's own 100 characters", () => {
    const title = capTitle("x".repeat(140))
    expect(title.length).toBe(100)
    expect(title.endsWith("...")).toBe(true)
  })

  test("empty and whitespace-only completions produce nothing, not an empty title", () => {
    expect(capTitle("")).toBeUndefined()
    expect(capTitle("   \n\n  ")).toBeUndefined()
  })
})

describe("sliceTitle — the no-model fallback", () => {
  test("collapses whitespace so a pasted block does not become a ragged title", () => {
    expect(sliceTitle("  fix   the\n\nflaky test  ")).toBe("fix the flaky test")
  })

  test("truncates past 50 characters", () => {
    const title = sliceTitle("y".repeat(120))
    expect(title.length).toBe(53)
    expect(title.endsWith("...")).toBe(true)
  })

  test("nothing in, nothing out", () => {
    expect(sliceTitle("   ")).toBeUndefined()
  })
})

describe("userText", () => {
  test("joins the text parts in order", () => {
    const message = { parts: [{ type: "text", text: "first" }, { type: "text", text: "second" }] }
    expect(userText(message)).toBe("first\nsecond")
  })

  test("ignores file parts and parts opencode marked ignored", () => {
    const message = {
      parts: [
        { type: "file", url: "file:///tmp/a.ts", mime: "text/plain" },
        { type: "text", text: "keep me" },
        { type: "text", text: "drop me", ignored: true },
      ],
    }
    expect(userText(message)).toBe("keep me")
  })

  test("a message with no parts yields an empty string, never a throw", () => {
    expect(userText(undefined)).toBe("")
    expect(userText({})).toBe("")
  })
})

describe("generateTitle", () => {
  const config = { ...DEFAULTS, timeoutMs: 1000 }
  const ok = (content) => async () => ({ ok: true, json: async () => ({ choices: [{ message: { content } }] }) })

  test("returns the model's line", async () => {
    expect(await generateTitle(config, "why is app.js failing", ok("app.js failure investigation"))).toEqual({
      title: "app.js failure investigation",
    })
  })

  test("truncates the prompt to maxChars — the whole point of this path", async () => {
    let sent
    const capture = async (_url, init) => {
      sent = JSON.parse(init.body)
      return { ok: true, json: async () => ({ choices: [{ message: { content: "Long paste" } }] }) }
    }
    await generateTitle(config, "z".repeat(50_000), capture)
    const prompt = sent.messages.at(-1).content
    expect(prompt.length).toBeLessThanOrEqual(config.maxChars + 64)
    expect(prompt).toContain("Generate a title for this conversation:")
  })

  test("an HTTP failure is reported, not thrown", async () => {
    const res = await generateTitle(config, "hello", async () => ({ ok: false, status: 400, text: async () => "" }))
    expect(res.error).toBe("HTTP 400")
    expect(res.title).toBeUndefined()
  })

  test("a refused connection is reported, not thrown", async () => {
    const res = await generateTitle(config, "hello", async () => {
      throw new Error("connect ECONNREFUSED")
    })
    expect(res.error).toContain("ECONNREFUSED")
  })

  test("an empty completion is an error so the caller falls back to the slice", async () => {
    const res = await generateTitle(config, "hello", ok("   "))
    expect(res.error).toBe("empty completion")
  })
})

describe("plugin surface", () => {
  test("exactly one export — a second one can poison the whole load batch", async () => {
    const module = await import("../plugin/title-fallback.js")
    expect(Object.keys(module)).toEqual(["TitleFallback"])
  })

  test("a non-idle event is ignored without touching the client", async () => {
    let touched = false
    const client = { session: { get: async () => ((touched = true), {}) } }
    const hooks = await TitleFallback({ client, directory: "/tmp" })
    await hooks.event({ event: { type: "session.updated", properties: { sessionID: "ses_1" } } })
    expect(touched).toBe(false)
  })

  test("a session that already has a real title is left alone", async () => {
    const calls = []
    const client = {
      session: {
        get: async () => ({ data: { id: "ses_1", title: "Rate limiting implementation" } }),
        update: async (args) => calls.push(args),
      },
    }
    const hooks = await TitleFallback({ client, directory: "/tmp" })
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_1" } } })
    expect(calls).toEqual([])
  })

  test("a child session is left alone even when its title is the default shape", async () => {
    const calls = []
    const client = {
      session: {
        get: async () => ({
          data: { id: "ses_2", parentID: "ses_1", title: "New session - 2026-08-23T00:32:58.489Z" },
        }),
        update: async (args) => calls.push(args),
      },
    }
    const hooks = await TitleFallback({ client, directory: "/tmp" })
    await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_2" } } })
    expect(calls).toEqual([])
  })

  test("one attempt per session — a second idle does not re-read it", async () => {
    let gets = 0
    const client = {
      session: {
        get: async () => (gets++, { data: { id: "ses_3", title: "already named" } }),
        update: async () => ({}),
      },
    }
    const hooks = await TitleFallback({ client, directory: "/tmp" })
    const idle = { event: { type: "session.idle", properties: { sessionID: "ses_3" } } }
    await hooks.event(idle)
    await hooks.event(idle)
    expect(gets).toBe(1)
  })

  test("debug mode records the declines that are otherwise silent", async () => {
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "title-fallback-debug-"))
    const previous = { dir: process.env.OPENCODE_TITLE_FALLBACK_LOG_DIR, on: process.env.OPENCODE_TITLE_FALLBACK_DEBUG }
    process.env.OPENCODE_TITLE_FALLBACK_LOG_DIR = logDir
    process.env.OPENCODE_TITLE_FALLBACK_DEBUG = "1"
    try {
      const client = {
        session: { get: async () => ({ data: { id: "ses_5", title: "Rate limiting implementation" } }) },
      }
      const hooks = await TitleFallback({ client, directory: "/tmp" })
      await hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_5" } } })

      const lines = fs
        .readdirSync(logDir)
        .flatMap((f) => fs.readFileSync(path.join(logDir, f), "utf8").trim().split("\n"))
        .filter(Boolean)
        .map((l) => JSON.parse(l))
      expect(lines.map((l) => l.event)).toContain("event.seen")
      const declined = lines.find((l) => l.event === "declined")
      expect(declined?.reason).toBe("title already set")
    } finally {
      process.env.OPENCODE_TITLE_FALLBACK_LOG_DIR = previous.dir
      if (previous.on === undefined) delete process.env.OPENCODE_TITLE_FALLBACK_DEBUG
      else process.env.OPENCODE_TITLE_FALLBACK_DEBUG = previous.on
    }
  })

  test("a client that throws on every call never surfaces as an error", async () => {
    const client = {
      session: {
        get: async () => {
          throw new Error("boom")
        },
        messages: async () => {
          throw new Error("boom")
        },
        update: async () => {
          throw new Error("boom")
        },
      },
    }
    const hooks = await TitleFallback({ client, directory: "/tmp" })
    expect(
      hooks.event({ event: { type: "session.idle", properties: { sessionID: "ses_4" } } }),
    ).resolves.toBeUndefined()
  })
})
