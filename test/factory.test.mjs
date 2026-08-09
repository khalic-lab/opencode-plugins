/**
 * Factory-level tests: drive LocalClassifierPlugin through its real event
 * hook with a mocked SDK client and a mocked fetch, and assert the
 * highest-consequence invariants:
 *   - shadow mode NEVER replies, whatever the verdict
 *   - enforce mode replies exactly "once", via the SDK client
 *   - classifier failure in enforce mode → no reply (fail-closed)
 *   - our own reply coming back on the bus is logged self.decision
 *   - vetoHeadless throws on RISKY and on classifier failure
 */
import { describe, test, expect, afterEach } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { LocalClassifier as LocalClassifierPlugin } from "../plugin/local-classifier.js"

const realFetch = globalThis.fetch
afterEach(() => { globalThis.fetch = realFetch })

function mockFetch(verdictText) {
  return async (url) => {
    if (String(url).endsWith("/models")) return { ok: true, status: 200, json: async () => ({ data: [] }) }
    if (verdictText instanceof Error) throw verdictText
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: verdictText } }] }) }
  }
}

function mockClient() {
  const calls = []
  return {
    calls,
    postSessionIdPermissionsPermissionId: async (opts) => { calls.push(opts); return {} },
  }
}

async function makePlugin({ mode, verdict, client }) {
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
  globalThis.fetch = mockFetch(verdict)
  const hooks = await LocalClassifierPlugin(
    { client, worktree: "/", directory: null },
    { mode, logDir, countdownMs: 500, vetoHeadless: false },
  )
  const readLog = () =>
    fs.readdirSync(logDir).flatMap((f) =>
      fs.readFileSync(path.join(logDir, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)),
    )
  return { hooks, readLog, logDir }
}

const asked = (id) => ({
  event: {
    type: "permission.asked",
    properties: {
      id, sessionID: "ses_t", permission: "bash",
      patterns: ["ls"], metadata: { command: "ls ." }, always: [],
    },
  },
})

describe("plugin factory invariants", () => {
  test("shadow: SAFE verdict logs would_approve and never touches the client", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "shadow", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_1"))
    expect(client.calls.length).toBe(0)
    const log = readLog()
    expect(log.find((l) => l.event === "action")?.decided).toBe("would_approve")
    expect(log.find((l) => l.event === "classification")?.subject).toBe("ls .")
  })

  test("enforce: SAFE verdict replies exactly 'once' via the SDK client", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_2"))
    expect(client.calls.length).toBe(1)
    expect(client.calls[0].body).toEqual({ response: "once" })
    expect(client.calls[0].path).toEqual({ id: "ses_t", permissionID: "per_2" })
    expect(readLog().find((l) => l.event === "action")?.decided).toBe("approved")
  })

  test("enforce: RISKY verdict never replies", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: RISKY\nREASON: no", client })
    await hooks.event(asked("per_3"))
    expect(client.calls.length).toBe(0)
    expect(readLog().find((l) => l.event === "action")?.decided).toBe("none")
  })

  test("enforce: classifier failure never replies (fail-closed)", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: new Error("ECONNREFUSED"), client })
    await hooks.event(asked("per_4"))
    expect(client.calls.length).toBe(0)
    expect(readLog().find((l) => l.event === "action")?.decided).toBe("none")
  })

  test("our own reply on the bus is self.decision; a real human reply is human.decision", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_5"))
    // our reply comes back on the bus
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: "per_5", reply: "once" } } })
    const log = readLog()
    expect(log.some((l) => l.event === "self.decision" && l.permission_id === "per_5")).toBe(true)
    expect(log.some((l) => l.event === "human.decision" && l.permission_id === "per_5")).toBe(false)
  })

  test("shadow: a human reply is human.decision with the verdict joined", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "shadow", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_6"))
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: "per_6", reply: "reject" } } })
    const d = readLog().find((l) => l.event === "human.decision" && l.permission_id === "per_6")
    expect(d.response).toBe("reject")
    expect(d.classifier_verdict).toBe("SAFE")
    expect(typeof d.ms_since_ask).toBe("number")
  })

  test("vetoHeadless: RISKY and classifier failure both throw; SAFE passes", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: RISKY\nREASON: no")
    let hooks = await LocalClassifierPlugin(
      { client, worktree: "/", directory: null },
      { mode: "shadow", logDir, vetoHeadless: true },
    )
    const call = (cmd) => hooks["tool.execute.before"]({ tool: "bash", callID: "c1", sessionID: "s" }, { args: { command: cmd } })
    await expect(call("rm -rf /")).rejects.toThrow(/blocked/)
    globalThis.fetch = mockFetch(new Error("down"))
    await expect(call("ls")).rejects.toThrow(/fail-closed/)
    globalThis.fetch = mockFetch("VERDICT: SAFE\nREASON: ok")
    await expect(call("ls")).resolves.toBeUndefined()
    // mode off is the kill switch for the veto hook too
    globalThis.fetch = mockFetch("VERDICT: RISKY\nREASON: no")
    hooks = await LocalClassifierPlugin(
      { client, worktree: "/", directory: null },
      { mode: "off", logDir, vetoHeadless: true },
    )
    await expect(call("rm -rf /")).resolves.toBeUndefined()
  })
})
