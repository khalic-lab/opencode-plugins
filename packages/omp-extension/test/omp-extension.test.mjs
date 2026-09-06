import { describe, test, expect } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { LocalClassifier } from "opencode-local-classifier"
import ompLocalClassifier, { internals } from "../omp-local-classifier.js"

const I = LocalClassifier.internals

const { subjectFor, decide, OMP_DEFAULTS } = internals

const noopLog = () => true
const counters = () => ({ checked: 0, safe: 0, risky: 0, failed: 0, blocked: 0, asked: 0 })

describe("subject extraction", () => {
  /**
   * The invariant the whole corpus rests on. opencode judges
   * `metadata.command`; omp judges `input.command`. If these ever stop being
   * the same bytes, verdicts from the two hosts may no longer be pooled and
   * PROMPT_VERSION has to fork — so this asserts it instead of trusting the
   * 2026-09-03 probe forever.
   */
  test("bash subject is the command verbatim", () => {
    const command = "cd /tmp && rm -rf build || echo 'no build'"
    const found = subjectFor("bash", { command })
    expect(found).not.toBeNull()
    expect(found.kind).toBe("bash")
    expect(found.subject).toBe(command)
  })

  test("no command, no classification — never a reconstructed guess", () => {
    expect(subjectFor("bash", {})).toBeNull()
    expect(subjectFor("bash", { command: "   " })).toBeNull()
    expect(subjectFor("bash", { cmd: "echo hi" })).toBeNull()
  })

  test("unknown tools are not ours to judge", () => {
    expect(subjectFor("read", { file_path: "/etc/passwd" })).toBeNull()
    expect(subjectFor("web_search", { query: "x" })).toBeNull()
  })

  /**
   * write/edit must never reach the model in v1. DIRECTORY_SYSTEM_PROMPT
   * expects opencode's two-line subject (exact file AND the `dirname + "/*"`
   * glob the approval grants); omp has no glob to send, so a bare path is
   * off-distribution for a prompt describing something not present. Those
   * tools are handled deterministically by judgeWritePath instead.
   */
  test("path tools never produce a model subject", () => {
    expect(subjectFor("write", { file_path: "/tmp/a.txt" })).toBeNull()
    expect(subjectFor("edit", { file_path: "/etc/hosts" })).toBeNull()
    expect(subjectFor("multiedit", { file_path: "/tmp/b.txt" })).toBeNull()
  })
})

describe("decide()", () => {
  const enforceBlock = { mode: "enforce", riskyAction: "block" }
  const enforceConfirm = { mode: "enforce", riskyAction: "confirm" }

  test("shadow never acts", async () => {
    const c = counters()
    const out = await decide({ hasUI: true }, { mode: "shadow", riskyAction: "block" }, "why", c, noopLog)
    expect(out).toBeUndefined()
    expect(c.blocked).toBe(0)
  })

  test("enforce + block blocks with a reason", async () => {
    const c = counters()
    const out = await decide({ hasUI: true }, enforceBlock, "classified RISKY", c, noopLog)
    expect(out?.block).toBe(true)
    expect(out.reason).toContain("classified RISKY")
    expect(c.blocked).toBe(1)
  })

  /**
   * The headless hole this design must not have. Subagents and print mode set
   * hasUI=false, and omp's no-UI ctx.ui.confirm resolves false immediately —
   * so the confirm posture has to degrade to a block, never to an allow.
   */
  test("confirm degrades to block with no UI", async () => {
    const c = counters()
    const out = await decide({ hasUI: false }, enforceConfirm, "classifier http_500", c, noopLog)
    expect(out?.block).toBe(true)
    expect(c.asked).toBe(0)
    expect(c.blocked).toBe(1)
  })

  test("confirm accepted lets the call through and is audited", async () => {
    const c = counters()
    const events = []
    const ctx = { hasUI: true, ui: { confirm: async () => true } }
    const out = await decide(ctx, enforceConfirm, "classified RISKY", c, (e) => events.push(e))
    expect(out).toBeUndefined()
    expect(c.asked).toBe(1)
    expect(events).toContain("action.human_override")
  })

  test("confirm declined blocks", async () => {
    const c = counters()
    const ctx = { hasUI: true, ui: { confirm: async () => false } }
    const out = await decide(ctx, enforceConfirm, "classified RISKY", c, noopLog)
    expect(out?.block).toBe(true)
    expect(c.blocked).toBe(1)
  })

  test("a throwing confirm blocks rather than falling through", async () => {
    const c = counters()
    const ctx = {
      hasUI: true,
      ui: {
        confirm: async () => {
          throw new Error("no dialog host")
        },
      },
    }
    const out = await decide(ctx, enforceConfirm, "classified RISKY", c, noopLog)
    expect(out?.block).toBe(true)
  })
})

describe("extraRoots", () => {
  const { normalizeExtraRoots, rootFor } = internals
  const home = os.homedir()

  test("absolute roots are kept and ~ is expanded", () => {
    const problems = []
    const out = normalizeExtraRoots(["/usr/local/src/khalic-lab/x", "~/code/y"], problems)
    expect(out).toEqual(["/usr/local/src/khalic-lab/x", path.join(home, "code/y")])
    expect(problems).toEqual([])
  })

  /**
   * The guard that matters: a root at or above HOME, or `/`, or a system
   * directory would switch the boundary rule off for most of the disk. These
   * are rejected, not clamped — a silently narrowed root looks like it worked.
   */
  test("over-broad roots are rejected with a reported problem", () => {
    for (const bad of ["/", home, "~", "/etc", "/usr", path.dirname(home)]) {
      const problems = []
      expect(normalizeExtraRoots([bad], problems)).toEqual([])
      expect(problems.length).toBe(1)
    }
  })

  test("malformed entries are dropped individually, not fatally", () => {
    const problems = []
    const out = normalizeExtraRoots(["/tmp/ok", "", 42, null, "/tmp/ok2"], problems)
    expect(out).toEqual(["/tmp/ok", "/tmp/ok2"])
    expect(problems.length).toBe(3)
  })

  test("a non-array is refused whole", () => {
    const problems = []
    expect(normalizeExtraRoots("/tmp/nope", problems)).toEqual([])
    expect(problems.length).toBe(1)
    expect(normalizeExtraRoots(undefined, [])).toEqual([])
  })

  test("rootFor matches the tree but not a sibling with a shared prefix", () => {
    const roots = ["/usr/local/src/spike"]
    expect(rootFor("/usr/local/src/spike", roots)).toBe("/usr/local/src/spike")
    expect(rootFor("/usr/local/src/spike/packages/a.js", roots)).toBe("/usr/local/src/spike")
    expect(rootFor("/usr/local/src/spike-other/a.js", roots)).toBeNull()
    expect(rootFor("/usr/local/src/elsewhere/a.js", roots)).toBeNull()
  })

  /**
   * A root is a widening of the boundary that is there to contain the project,
   * so only the user's own file may declare one. A cloned repository that
   * shipped its own .omp/local-classifier.json must not be able to let itself
   * out.
   */
  test("a project file cannot declare a root", () => {
    const { resolveOmpConfig } = internals
    const worktree = fs.mkdtempSync(path.join(os.tmpdir(), "omp-lc-wt-"))
    const escape = fs.mkdtempSync(path.join(os.tmpdir(), "omp-lc-escape-"))
    fs.mkdirSync(path.join(worktree, ".omp"), { recursive: true })
    fs.writeFileSync(
      path.join(worktree, ".omp", "local-classifier.json"),
      JSON.stringify({ extraRoots: [escape], outsideProjectAction: "ask" }),
    )
    const { config } = resolveOmpConfig({ worktree, env: {} })
    expect(config.extraRoots).not.toContain(escape)
  })

  test("declaring a root does not disable the sensitive-path rules inside it", () => {
    // judgeWritePath applies SENSITIVE_PATH_PATTERNS before the boundary rule,
    // so a credential path inside a declared root is still refused.
    const root = "/tmp/declared"
    expect(I.judgeWritePath(`${root}/.ssh/id_rsa`, root)).not.toBeNull()
    expect(I.judgeWritePath(`${root}/src/app.js`, root)).toBeNull()
  })
})

describe("defaults", () => {
  test("riskyAction defaults to block, so confirm is opt-in behind a raised timeout", () => {
    expect(OMP_DEFAULTS.riskyAction).toBe("block")
  })

  test("deterministic path rules are off by default", () => {
    expect(OMP_DEFAULTS.pathRules).toBe(false)
  })

  test("asking about a folder is opt-in; the shipped default still refuses", () => {
    expect(OMP_DEFAULTS.outsideProjectAction).toBe("deny")
  })

  test("there is no key that would send write/edit inputs to the model", () => {
    // extraRoots and outsideProjectAction move the boundary and who decides it.
    // Neither routes anything to the model.
    expect(Object.keys(OMP_DEFAULTS)).toEqual(["riskyAction", "pathRules", "extraRoots", "outsideProjectAction"])
  })
})

describe("registration", () => {
  test("the factory registers without touching runtime actions", () => {
    const handlers = new Map()
    const commands = new Map()
    const pi = {
      on: (name, fn) => handlers.set(name, fn),
      registerCommand: (name, def) => commands.set(name, def),
    }
    expect(() => ompLocalClassifier(pi)).not.toThrow()
    expect(handlers.has("tool_call")).toBe(true)
    expect(handlers.has("session_start")).toBe(true)
    expect(handlers.has("tool_approval_resolved")).toBe(true)
    expect(commands.has("classifier")).toBe(true)
  })

  test("tool_call stands aside when init never ran", async () => {
    const handlers = new Map()
    const pi = { on: (n, f) => handlers.set(n, f), registerCommand: () => {} }
    ompLocalClassifier(pi)
    const out = await handlers.get("tool_call")({ toolName: "bash", input: { command: "echo hi" } }, { cwd: "/tmp" })
    expect(out).toBeUndefined()
  })
})

/**
 * The interactive half of the boundary rule: a write outside the project can be
 * put to the human, and approving it remembers the folder. What must survive
 * every case here is that "remembered" only ever moves the project boundary —
 * it never unlocks a sensitive path, and it never turns a failure into an allow.
 */
describe("ask, then remember", () => {
  const { decidePath, candidateRootFor, loadRememberedRoots, rememberRoot } = internals

  const makeRepo = () => {
    const base = fs.mkdtempSync(path.join(os.tmpdir(), "omp-lc-"))
    const repo = path.join(base, "proj")
    fs.mkdirSync(path.join(repo, ".git"), { recursive: true })
    fs.mkdirSync(path.join(repo, "src"), { recursive: true })
    return { base, repo, session: path.join(base, "session") }
  }

  const askConfig = (over = {}) => ({
    mode: "enforce",
    riskyAction: "block",
    pathRules: true,
    extraRoots: [],
    outsideProjectAction: "ask",
    ...over,
  })

  const ctxWith = (cwd, confirm) => ({ cwd, hasUI: true, ui: { confirm } })

  test("the folder offered is the enclosing repository, not the file's directory", () => {
    const { repo } = makeRepo()
    expect(candidateRootFor(path.join(repo, "src", "app.js"))).toBe(repo)
    // No repository above it, so the file's own directory is the fallback.
    const loose = fs.mkdtempSync(path.join(os.tmpdir(), "omp-lc-loose-"))
    expect(candidateRootFor(path.join(loose, "note.txt"))).toBe(loose)
  })

  test("approving lets the write through and records the folder", async () => {
    const { repo, session } = makeRepo()
    const remembered = []
    const config = askConfig()
    const out = await decidePath(
      ctxWith(session, async () => true),
      config,
      "write",
      { filePath: path.join(repo, "src", "app.js") },
      counters(),
      noopLog,
      (root) => { remembered.push(root); return { added: true } },
    )
    expect(out).toBeUndefined()
    expect(remembered).toEqual([repo])
    // And it is live for the rest of the session, not only the next one.
    expect(config.extraRoots).toContain(repo)
  })

  test("declining blocks the write and remembers nothing", async () => {
    const { repo, session } = makeRepo()
    const remembered = []
    const out = await decidePath(
      ctxWith(session, async () => false),
      askConfig(),
      "write",
      { filePath: path.join(repo, "src", "app.js") },
      counters(),
      noopLog,
      (root) => { remembered.push(root); return { added: true } },
    )
    expect(out?.block).toBe(true)
    expect(remembered).toEqual([])
  })

  test("a prompt that throws blocks rather than falling through", async () => {
    const { repo, session } = makeRepo()
    const out = await decidePath(
      ctxWith(session, async () => { throw new Error("no ui") }),
      askConfig(),
      "write",
      { filePath: path.join(repo, "src", "app.js") },
      counters(),
      noopLog,
      () => ({ added: true }),
    )
    expect(out?.block).toBe(true)
    expect(out.reason).toContain("confirm unavailable")
  })

  /** The invariant this whole feature is built around. */
  test("a sensitive path is never offered, inside a candidate folder or a remembered one", async () => {
    const { repo, session } = makeRepo()
    let asked = 0
    const key = path.join(repo, ".ssh", "id_rsa")

    const cold = await decidePath(
      ctxWith(session, async () => { asked += 1; return true }),
      askConfig(),
      "write",
      { filePath: key },
      counters(),
      noopLog,
      () => ({ added: true }),
    )
    expect(cold?.block).toBe(true)
    expect(asked).toBe(0)

    // Same target, with the folder already approved: still refused, still silent.
    const warm = await decidePath(
      ctxWith(session, async () => { asked += 1; return true }),
      askConfig({ extraRoots: [repo] }),
      "write",
      { filePath: key },
      counters(),
      noopLog,
      () => ({ added: true }),
    )
    expect(warm?.block).toBe(true)
    expect(asked).toBe(0)
  })

  test("a folder we could not store is never offered", async () => {
    // candidateRootFor falls back to the file's own directory, which can be
    // anywhere. Offering a root the loader would drop asks forever.
    let asked = 0
    const out = await decidePath(
      ctxWith("/usr/local/src/session", async () => { asked += 1; return true }),
      askConfig(),
      "write",
      { filePath: path.join(os.homedir(), "notes.txt") },
      counters(),
      noopLog,
      () => ({ added: true }),
    )
    expect(out?.block).toBe(true)
    expect(asked).toBe(0)
  })

  test("nobody is asked under the default posture, or with no UI to ask in", async () => {
    const { repo, session } = makeRepo()
    let asked = 0
    const confirm = async () => { asked += 1; return true }
    const target = { filePath: path.join(repo, "src", "app.js") }

    const denied = await decidePath(ctxWith(session, confirm), askConfig({ outsideProjectAction: "deny" }),
      "write", target, counters(), noopLog, () => ({ added: true }))
    expect(denied?.block).toBe(true)

    const headless = await decidePath({ cwd: session, hasUI: false, ui: { confirm } }, askConfig(),
      "write", target, counters(), noopLog, () => ({ added: true }))
    expect(headless?.block).toBe(true)

    expect(asked).toBe(0)
  })

  test("shadow mode reports what it would have asked and blocks nothing", async () => {
    const { repo, session } = makeRepo()
    let asked = 0
    const out = await decidePath(
      ctxWith(session, async () => { asked += 1; return true }),
      askConfig({ mode: "shadow" }),
      "write",
      { filePath: path.join(repo, "src", "app.js") },
      counters(),
      noopLog,
      () => ({ added: true }),
    )
    expect(out).toBeUndefined()
    expect(asked).toBe(0)
  })

  test("the state file round-trips, is idempotent, and is re-validated on read", () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "omp-lc-state-"))
    const file = path.join(dir, "remembered-roots.json")
    const repo = path.join(dir, "proj")

    expect(loadRememberedRoots(file)).toEqual([])
    expect(rememberRoot(repo, file).added).toBe(true)
    expect(rememberRoot(repo, file).added).toBe(false)
    expect(loadRememberedRoots(file)).toEqual([repo])

    // A hand-edited over-broad entry must not take effect just because it is
    // in our own file.
    fs.writeFileSync(file, JSON.stringify({ roots: [repo, os.homedir(), "/"] }))
    expect(loadRememberedRoots(file)).toEqual([repo])
  })
})
