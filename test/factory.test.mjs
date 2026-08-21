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
// The tuple `options` layer is untrusted by default (a cloned repo can supply
// it), so the harness declares trust the way a real operator would — through
// the env, which a checkout cannot write.
process.env.OPENCODE_LOCAL_CLASSIFIER_TRUST_OPTIONS = "1"
afterEach(() => { globalThis.fetch = realFetch })

function mockFetch(verdictText) {
  return async (url) => {
    if (String(url).endsWith("/models")) return { ok: true, status: 200, json: async () => ({ data: [] }) }
    if (verdictText instanceof Error) throw verdictText
    return { ok: true, status: 200, json: async () => ({ choices: [{ message: { content: verdictText } }] }) }
  }
}

/**
 * `order` records reply and toast calls in the sequence they happened: the
 * countdown toast is only worth anything if it lands BEFORE the reply, while
 * the human can still abort.
 */
function mockClient({ tui = "ok" } = {}) {
  const calls = []
  const toasts = []
  const order = []
  const toastTimes = []
  const client = {
    calls,
    toasts,
    order,
    toastTimes,
    postSessionIdPermissionsPermissionId: async (opts) => { calls.push(opts); order.push("reply"); return {} },
  }
  if (tui === "ok") {
    // The real route answers with a boolean: `true` once the event is published.
    client.tui = { showToast: async (opts) => { toasts.push(opts); toastTimes.push(Date.now()); order.push("toast"); return { data: true } } }
  } else if (tui === "throws") {
    client.tui = { showToast: async () => { order.push("toast-threw"); throw new Error("tui gone") } }
  } else if (tui === "argmapped") {
    // opencode 1.18.15 bundles a second client shape that reads directory /
    // workspace / title / message / variant / duration off its FIRST argument.
    // Two parameters is the only thing that tells it apart from the other.
    client.tui = { showToast: async (params, _opts) => { toasts.push(params); order.push("toast"); return { data: true } } }
  } else if (tui === "notdelivered") {
    // Published, rendered by nobody — what a workspace mismatch looks like.
    client.tui = { showToast: async (opts) => { toasts.push(opts); order.push("toast"); return { data: false } } }
  }
  return client
}

async function makePlugin({ mode, verdict, client, logDir: forcedLogDir, directory = null }) {
  const logDir = forcedLogDir ?? fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
  globalThis.fetch = mockFetch(verdict)
  const hooks = await LocalClassifierPlugin(
    { client, worktree: "/", directory },
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

  test("vetoHeadless in ENFORCE: RISKY and classifier failure both throw; SAFE passes", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: RISKY\nREASON: no")
    let hooks = await LocalClassifierPlugin(
      { client, worktree: "/", directory: null },
      { mode: "enforce", logDir, vetoHeadless: true },
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

  test("vetoHeadless in SHADOW observes only: logs veto_would_block, never throws", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: RISKY\nREASON: no")
    const hooks = await LocalClassifierPlugin(
      { client, worktree: "/", directory: null },
      { mode: "shadow", logDir, vetoHeadless: true },
    )
    await expect(
      hooks["tool.execute.before"]({ tool: "bash", callID: "c9", sessionID: "s" }, { args: { command: "rm -rf /" } }),
    ).resolves.toBeUndefined()
    const log = fs.readdirSync(logDir).flatMap((f) =>
      fs.readFileSync(path.join(logDir, f), "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l)),
    )
    expect(log.some((l) => l.event === "action" && l.decided === "veto_would_block")).toBe(true)
    expect(log.some((l) => l.event === "action" && l.decided === "veto_block")).toBe(false)
  })

  test("veto blocks a write outside the project and one to code that runs on its own", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: SAFE\nREASON: ok")
    const hooks = await LocalClassifierPlugin(
      { client, worktree: "/w/proj", directory: "/w/proj" },
      { mode: "enforce", logDir, vetoHeadless: true },
    )
    const write = (filePath) =>
      hooks["tool.execute.before"]({ tool: "write", callID: "c2", sessionID: "s" }, { args: { filePath, content: "x" } })
    await expect(write("/w/proj/src/app.ts")).resolves.toBeUndefined()
    await expect(write("/Users/someone/.zshrc")).rejects.toThrow(/blocked/)
    await expect(write("/w/proj/.git/hooks/pre-commit")).rejects.toThrow(/sensitive path/)
  })

  test("veto classifies a read that leaves the project, and ignores one that does not", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: RISKY\nREASON: private key")
    const hooks = await LocalClassifierPlugin(
      { client, worktree: "/w/proj", directory: "/w/proj" },
      { mode: "enforce", logDir, vetoHeadless: true },
    )
    const read = (filePath) =>
      hooks["tool.execute.before"]({ tool: "read", callID: "c3", sessionID: "s" }, { args: { filePath } })
    await expect(read("/w/proj/src/app.ts")).resolves.toBeUndefined()
    await expect(read("/Users/someone/.ssh/id_rsa")).rejects.toThrow(/blocked/)
  })

  test("siblings still awaiting their verdict are stamped too (the normal burst shape)", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "shadow", verdict: "VERDICT: SAFE\nREASON: ok", client })
    // Fire three asks WITHOUT awaiting: with the serial classifier queue, the
    // siblings are still mid-classification when the human answers one of them.
    const inFlight = [hooks.event(asked("per_x1")), hooks.event(asked("per_x2")), hooks.event(asked("per_x3"))]
    const reply = (id, r) => hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: id, reply: r } } })
    await reply("per_x2", "reject") // the human rejects the middle prompt
    await reply("per_x1", "reject") // …and the server echoes it onto the others
    await reply("per_x3", "reject")
    await Promise.all(inFlight)
    const decisions = readLog().filter((l) => l.event === "human.decision")
    expect(decisions.find((d) => d.permission_id === "per_x2").cascade_sibling).toBeNull()
    expect(decisions.find((d) => d.permission_id === "per_x1").cascade_sibling).toBe("per_x2")
    expect(decisions.find((d) => d.permission_id === "per_x3").cascade_sibling).toBe("per_x2")
  })

  test("a cascade sibling is stamped so the analyzer can tell it from the real reject", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "shadow", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_a"))
    await hooks.event(asked("per_b"))
    // The human rejects ONE prompt; opencode republishes the reject for every
    // other pending permission in the session.
    const reply = (id, r) => hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: id, reply: r } } })
    await reply("per_a", "reject")
    await reply("per_b", "reject")
    const decisions = readLog().filter((l) => l.event === "human.decision")
    expect(decisions.find((d) => d.permission_id === "per_a").cascade_sibling).toBeNull()
    expect(decisions.find((d) => d.permission_id === "per_b").cascade_sibling).toBe("per_a")
  })

  test("enforce writes the approval intent BEFORE the reply leaves", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_7"))
    const events = readLog().map((l) => l.event)
    expect(events.indexOf("action.reply_intent")).toBeGreaterThan(-1)
    expect(events.indexOf("action.reply_intent")).toBeLessThan(events.indexOf("action.reply_attempt"))
  })

  test("a reply whose transport reported failure is still ours, not a human approval", async () => {
    const client = { calls: [], postSessionIdPermissionsPermissionId: async () => ({ error: "boom" }) }
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_8"))
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: "per_8", reply: "once" } } })
    const log = readLog()
    expect(log.find((l) => l.event === "action" && l.decided)?.decided).toBeDefined()
    expect(log.some((l) => l.event === "self.decision" && l.permission_id === "per_8")).toBe(true)
    expect(log.some((l) => l.event === "human.decision" && l.permission_id === "per_8")).toBe(false)
  })
})

/**
 * The TUI toast is the only thing that explains an auto-approval to the person
 * watching. Without it, enforce mode makes a prompt vanish with no reason
 * given, and a REFUSED auto-approval looks identical to a working one.
 *
 * Two invariants dominate:
 *   - the countdown toast must land BEFORE the reply, or it is not an abort
 *     window, it is an obituary;
 *   - the toast is decoration. It must never be able to break, delay past its
 *     own failure, or alter the approval it is describing.
 */
describe("enforce-mode toasts explain the decision", () => {
  test("SAFE announces the pending auto-approval, with the reason, before replying", async () => {
    const client = mockClient()
    const { hooks } = await makePlugin({
      mode: "enforce", verdict: "VERDICT: SAFE\nREASON: routine read-only inspection", client,
    })
    await hooks.event(asked("per_toast1"))
    expect(client.toasts.length).toBe(1)
    const body = client.toasts[0].body
    // Amber, not blue: this is the one toast with a deadline on it. `info` was
    // the dimmest variant and the easiest of the three to miss entirely.
    expect(body.variant).toBe("warning")
    expect(body.message).toContain("routine read-only inspection")
    // The harness sets countdownMs: 500 — the toast should last the window.
    expect(body.duration).toBe(500)
    expect(client.order).toEqual(["toast", "reply"])
  })

  test("a refused auto-approval says so, even when the log is the thing that broke", async () => {
    // A path that cannot be a directory: mkdir fails, every log write fails,
    // and the plugin refuses to approve without a durable audit line. The
    // toast is then the ONLY signal the human gets.
    const notADir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-")), "file")
    fs.writeFileSync(notADir, "x")
    const client = mockClient()
    const { hooks } = await makePlugin({
      mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client, logDir: path.join(notADir, "logs"),
    })
    await hooks.event(asked("per_toast2"))
    expect(client.calls.length).toBe(0) // refused
    expect(client.toasts.length).toBe(1)
    // Blue, not amber: nothing is on fire and no deadline is running — the
    // prompt is simply still yours to answer. Amber belongs to the countdown.
    expect(client.toasts[0].body.variant).toBe("info")
    expect(client.toasts[0].body.message).toMatch(/not durably logged/i)
  })

  test("a reply that never reached opencode is reported as an error, not silence", async () => {
    const client = mockClient()
    client.postSessionIdPermissionsPermissionId = async () => { client.order.push("reply"); return { error: "boom" } }
    const { hooks } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_toast3"))
    expect(client.toasts.some((t) => t.body.variant === "error")).toBe(true)
  })

  test("RISKY is not announced — the prompt stays and speaks for itself", async () => {
    const client = mockClient()
    const { hooks } = await makePlugin({ mode: "enforce", verdict: "VERDICT: RISKY\nREASON: destructive", client })
    await hooks.event(asked("per_toast4"))
    expect(client.toasts.length).toBe(0)
  })

  test("shadow mode never toasts — observation stays invisible", async () => {
    const client = mockClient()
    const { hooks } = await makePlugin({ mode: "shadow", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_toast5"))
    expect(client.toasts.length).toBe(0)
  })

  test("a client with no tui namespace still approves", async () => {
    const client = mockClient({ tui: "none" })
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_toast6"))
    expect(client.calls.length).toBe(1)
    expect(readLog().find((l) => l.event === "action" && l.decided)?.decided).toBe("approved")
  })

  test("a toast that throws never touches the approval, and leaves a trace", async () => {
    const client = mockClient({ tui: "throws" })
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    await hooks.event(asked("per_toast7"))
    expect(client.calls.length).toBe(1)
    expect(readLog().find((l) => l.event === "action" && l.decided)?.decided).toBe("approved")
    expect(readLog().some((l) => l.event === "ui.toast" && l.ok === false)).toBe(true)
  })

  test("toasts: false turns them off without touching the decision", async () => {
    const client = mockClient()
    const logDir = fs.mkdtempSync(path.join(os.tmpdir(), "lc-test-"))
    globalThis.fetch = mockFetch("VERDICT: SAFE\nREASON: ok")
    const hooks = await LocalClassifierPlugin(
      { client, worktree: "/", directory: null },
      { mode: "enforce", logDir, countdownMs: 500, vetoHeadless: false, toasts: false },
    )
    await hooks.event(asked("per_toast8"))
    expect(client.toasts.length).toBe(0)
    expect(client.calls.length).toBe(1)
  })
})

describe("toasts do not describe a prompt that is already gone", () => {
  test("a human who answered during classification gets no auto-approval toast", async () => {
    const client = mockClient()
    const { hooks } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: ok", client })
    const inFlight = hooks.event(asked("per_toast9"))
    await hooks.event({ event: { type: "permission.replied", properties: { sessionID: "ses_t", requestID: "per_toast9", reply: "reject" } } })
    await inFlight
    expect(client.toasts.some((t) => t.body.variant === "warning")).toBe(false)
    expect(client.calls.length).toBe(0)
  })
})

/**
 * Delivery, as distinct from decoration. At opencode 1.18.15 the server's
 * handler is `publish(ToastShow, payload), !0` — it answers `true` the instant
 * the event is on the bus, before any TUI has looked at it. The TUI subscriber
 * then drops events addressed elsewhere:
 *
 *   on("tui.toast.show", (e, {workspace: z}) => {
 *     if (z !== k.workspace.current()) return
 *     ...
 *   })
 *
 * So "the call did not error" says nothing about whether a box appeared, and a
 * toast posted with no directory can be accepted and still render nowhere.
 * These tests pin the two halves: address the toast, and record what came back.
 */
describe("toasts are addressed, and their delivery is recorded", () => {
  test("the toast carries the plugin's directory so the TUI can resolve its workspace", async () => {
    const client = mockClient()
    const { hooks } = await makePlugin({
      mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client, directory: "/usr/local/src/proj",
    })
    await hooks.event(asked("per_dir1"))
    expect(client.toasts.length).toBeGreaterThan(0)
    expect(client.toasts[0].query?.directory).toBe("/usr/local/src/proj")
  })

  test("an arg-mapped SDK client gets the fields at the top level, not under body", async () => {
    const client = mockClient({ tui: "argmapped" })
    const { hooks } = await makePlugin({
      mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client, directory: "/usr/local/src/proj",
    })
    await hooks.event(asked("per_dir2"))
    expect(client.toasts.length).toBeGreaterThan(0)
    expect(client.toasts[0].message).toMatch(/fine/)
    expect(client.toasts[0].directory).toBe("/usr/local/src/proj")
  })

  test("a delivered toast is logged too, so silence stops meaning success", async () => {
    const client = mockClient()
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client })
    await hooks.event(asked("per_dir3"))
    expect(readLog().some((l) => l.event === "ui.toast" && l.ok === true)).toBe(true)
  })

  test("a toast the server publishes but nobody renders is not counted as delivered", async () => {
    const client = mockClient({ tui: "notdelivered" })
    const { hooks, readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client })
    await hooks.event(asked("per_dir4"))
    expect(readLog().some((l) => l.event === "ui.toast" && l.ok === false)).toBe(true)
  })
})

/**
 * The probe exists because there is no other way to test this. opencode 1.18.15
 * runs server and TUI in one process with no socket bound, so a toast cannot be
 * posted by hand from outside — and every real toast fires while the permission
 * dialog is on screen, which confounds "never delivered" with "delivered and
 * covered". Firing at init, with nothing else on screen, separates the two.
 */
describe("the toast probe fires after the TUI boot race, not into it", () => {
  // anomalyco/opencode#38527 (open, unfixed through v1.18.21): a server plugin
  // runs during instance bootstrap, BEFORE the TUI has subscribed to
  // "tui.toast.show", and the event is non-durable — so a toast sent from the
  // factory body is dropped while the SDK still answers {data:true}. A probe
  // fired at init therefore tests nothing except the race. It has to wait.
  const flush = (ms) => new Promise((r) => setTimeout(r, ms))

  test("the probe waits before firing, and does not hold up startup", async () => {
    process.env.OPENCODE_LOCAL_CLASSIFIER_TOAST_PROBE = "60"
    try {
      const client = mockClient()
      const { readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client })
      expect(client.toasts.length).toBe(0) // init returned without waiting on it
      expect(readLog().some((l) => l.event === "ui.toast_probe" && l.delay_ms === 60)).toBe(true)
      await flush(600)
      expect(client.toasts.map((t) => t.body.variant)).toEqual(["info", "success", "warning", "error"])
      // The TUI shows one toast at a time and each replaces the last. Fired
      // 13ms apart, the first three are overwritten before anyone sees them —
      // which is exactly what happened on the first real run. They must be
      // spaced, and by more than their own duration.
      const gaps = client.toastTimes.slice(1).map((t, i) => t - client.toastTimes[i])
      expect(gaps.every((g) => g >= 100)).toBe(true)
      expect(client.toasts.every((t) => t.body.duration <= 100)).toBe(true)
    } finally {
      delete process.env.OPENCODE_LOCAL_CLASSIFIER_TOAST_PROBE
    }
  })

  test("=0 and =false mean off, not \"on with the default delay\"", async () => {
    for (const off of ["0", "false"]) {
      process.env.OPENCODE_LOCAL_CLASSIFIER_TOAST_PROBE = off
      try {
        const client = mockClient()
        const { readLog } = await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client })
        // Not "no toast within 120ms" — that passes even when the probe armed
        // with the 8s default. Whether it armed at all is the question.
        expect(readLog().some((l) => l.event === "ui.toast_probe")).toBe(false)
      } finally {
        delete process.env.OPENCODE_LOCAL_CLASSIFIER_TOAST_PROBE
      }
    }
  })

  test("without the env var, init says nothing", async () => {
    const client = mockClient()
    await makePlugin({ mode: "enforce", verdict: "VERDICT: SAFE\nREASON: fine", client })
    await flush(200)
    expect(client.toasts.length).toBe(0)
  })
})
