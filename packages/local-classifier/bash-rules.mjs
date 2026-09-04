/**
 * bash-rules.mjs — a deterministic RISKY layer that runs BEFORE the model.
 *
 * WHY THIS EXISTS
 * ---------------
 * On 83 fresh hand-adjudicated commands every prompt design we tried misses the
 * SAME ten as false-SAFE, and nine of those ten are decidable without a model:
 * a force push, a credential file read, a script executed out of the session
 * scratchpad, a copy onto a destination that already exists. A 4B model reading
 * a 3,000-token rulebook is the wrong instrument for facts a regex and one
 * `stat` settle exactly.
 *
 * CONTRACT
 * --------
 *   judgeBashCommand(command, { projectDir, workingAreas, fs })
 *     → null                                       (no opinion — hand to the model)
 *     → { verdict: "RISKY", rule, why }            (assert an ask)
 *
 * In THIS pass the function NEVER asserts SAFE. A layer that can only add asks
 * cannot add misses: the worst it can do is friction, and every rule below is
 * measured against real traffic for exactly that. `fs` is injectable and is used
 * ONLY for existence/`isDirectory` checks on concrete paths. Nothing here ever
 * executes, spawns, or reads file CONTENT.
 *
 * WHICH RULEBOOK
 * --------------
 * The spec is the p10 few-shot v2 rulebook
 * (~/.local/share/opencode-local-classifier/candidates/p10-fewshot-v2.txt);
 * where it disagrees with the older BASH_SYSTEM_PROMPT in local-classifier.js,
 * p10 wins. Each rule below names the p10 clause it implements. Two places
 * where the rulebook and the shipped corpora disagree are called out inline
 * (`git clean -f`, `sudo`): the corpora win, because a rule that fires on a
 * case a human labelled SAFE is a bug in this layer, not in the corpus.
 *
 * WHAT THE CANONICALIZER DOES NOT DO
 * ----------------------------------
 * It is deliberately not a shell. It does not model: subshell scoping (a `cd`
 * inside `( )` or after a `|` is treated as if it persisted), arithmetic or
 * array expansion, `$@`/`$1`, alias or function definitions, `set -o` options,
 * brace expansion, globbing against the real filesystem, `trap`, or `exec`
 * redirection of the shell itself. It makes no attempt to defeat obfuscation —
 * `git ch''eckout`, `$(printf '\162\155')`, `IFS=/;v=r/m` — because a rule that
 * loses that arms race silently is worse than no rule; those stay the model's
 * job. Anything it cannot resolve concretely is left non-concrete, and every
 * rule that needs a concrete path simply declines to fire.
 */

import nodeFs from "node:fs"
import os from "node:os"
import path from "node:path"

// ---------------------------------------------------------------------------
// Places
// ---------------------------------------------------------------------------

/**
 * p10 PLACES: "Scratch is an ABSOLUTE /tmp, /private/tmp or /var/tmp path
 * only." A project-relative `tmp/` is a PROJECT directory, whatever it is
 * called — which is why these are matched as absolute prefixes after
 * resolution, never as a substring.
 */
export const SCRATCH_ROOTS = Object.freeze(["/private/tmp", "/tmp", "/var/tmp"])

/**
 * p10 PLACES: the agent's own working areas — the session scratchpad, the
 * project memory, and the plan files. Mirrors `ccOwnRoot` in
 * packages/cc-hook/cc-classifier-hook.mjs; the rest of ~/.claude is
 * configuration, not a working area.
 */
export function defaultWorkingAreas(home = os.homedir(), uid = typeof process.getuid === "function" ? process.getuid() : null) {
  const areas = []
  if (uid !== null) areas.push(`/private/tmp/claude-${uid}`, `/tmp/claude-${uid}`)
  areas.push(path.join(home, ".claude", "plans"))
  return areas
}

/**
 * p10 #6: "one planted in a drop directory such as ~/.local/bin or ~/bin".
 * NOT exempt from the execution rule, and NOT a place a truncation is excused.
 */
function dropDirs(home) {
  return [path.join(home, ".local", "bin"), path.join(home, "bin")]
}

/**
 * Write targets whose contents decide what runs later, or that hold
 * credentials. Mirrors SENSITIVE_PATH_PATTERNS in local-classifier.js — same
 * list, plus the ~/.claude clause the cc-hook expresses as code (`ccOwnRoot`).
 *
 * IMPORTANT: this list is applied to WRITE destinations only. The original is
 * used by judgeWritePath, which only ever sees writes. p10 #4 is explicit that
 * READING these is inspection ("cat or grep over /etc/*, ~/.zshrc or a plist"),
 * and the corpora agree — `cat ~/.gitconfig`, `grep -n 'export PATH' ~/.zshrc`
 * and `cat /etc/paths` are all labelled SAFE. Using this list on the read path
 * would flag them.
 */
const SENSITIVE_WRITE_PATTERNS = [
  /(^|\/)\.(bashrc|zshrc|zprofile|zshenv|profile|bash_profile|netrc|npmrc|pypirc|gitconfig)$/,
  /(^|\/)\.ssh(\/|$)/, /(^|\/)\.aws(\/|$)/, /(^|\/)\.gnupg(\/|$)/, /(^|\/)\.docker(\/|$)/,
  /(^|\/)\.git\/(hooks|config)/,
  /(^|\/)\.github\/workflows(\/|$)/,
  /(^|\/)Library\/(LaunchAgents|LaunchDaemons)(\/|$)/,
  /(^|\/)\.config\/opencode(\/|$)/,
  /(^|\/)\.env(\.|$)/,
  /^\/etc(\/|$)/, /^\/Library(\/|$)/, /^\/System(\/|$)/, /^\/private\/etc(\/|$)/,
]

// ---------------------------------------------------------------------------
// Credential kinds — p10 #5, "Credentials by KIND wherever the file lives"
// ---------------------------------------------------------------------------

/**
 * Basenames that ARE the credential. Matched exactly, never as a substring:
 * `src/lib/keychain-helper.ts` is a source file and is labelled SAFE, so
 * "contains the word keychain" can never be the test.
 */
const CREDENTIAL_BASENAMES = new Set([
  ".npmrc", ".pypirc", ".netrc", ".git-credentials", ".pgpass",
  "credentials", "credentials.json", "auth.json", "kubeconfig",
  "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ed25519_sk", "id_ecdsa_sk",
  // The gh TOKEN file. `~/.config/gh/config.yml` is the settings file and is
  // labelled SAFE, so this is by exact name, not by directory.
  "hosts.yml",
])

/** Extensions that carry private key material. `.crt`/`.pub` deliberately absent. */
const CREDENTIAL_EXTENSIONS = new Set([".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"])

/** Directory segments that are credential stores wherever they appear. */
const CREDENTIAL_DIRS = new Set([".ssh", ".aws", ".gnupg", ".kube"])

/**
 * @returns {string|null} a human phrase naming the kind, or null.
 */
function credentialKind(abs) {
  const base = path.basename(abs)
  const segs = abs.split("/")
  for (const s of segs) if (CREDENTIAL_DIRS.has(s)) return `${s} holds key material`
  // p10 #5 ".env*" — and a .env file is a credential kind wherever it lives,
  // which is why `.env.example` under the project counts (heldout3 labels it
  // RISKY) and `/tmp/.env.staging` counts too.
  if (/^\.env($|\.)/.test(base)) return "a .env file is credential material"
  if (CREDENTIAL_BASENAMES.has(base)) return `${base} holds credentials`
  if (base.endsWith(".pub")) return null
  const ext = base.includes(".") ? base.slice(base.lastIndexOf(".")) : ""
  if (CREDENTIAL_EXTENSIONS.has(ext)) return `${base} is private key material`
  if (/^id_[a-z0-9]+$/.test(base)) return `${base} is an SSH private key`
  if (/^secrets?\.[a-z0-9]+$/i.test(base)) return `${base} is a secrets file`
  if (/^service-account.*\.json$/i.test(base)) return `${base} is a service-account key`
  // ~/.docker/config.json holds the registry auth blob; a config.json anywhere
  // else is an ordinary config file (`~/.config/cc-tooling/config.json` SAFE).
  if (base === "config.json" && segs.includes(".docker")) return "the docker registry auth file"
  return null
}

/**
 * Verbs that read a file's CONTENT (or ship it somewhere). Keyed on the verb
 * rather than on the path appearing anywhere, because `ls -la ~/.ssh` and
 * `stat -f '%Sp' ~/.ssh/id_ed25519` are both labelled SAFE: listing and
 * stat-ing a key is not reading it.
 */
const CONTENT_READ_VERBS = new Set([
  "cat", "bat", "head", "tail", "tac", "nl", "less", "more", "strings", "xxd", "od", "hexdump",
  "grep", "egrep", "fgrep", "rg", "ag", "ack", "sed", "awk", "gawk", "cut", "paste", "sort", "uniq",
  "wc", "tr", "fold", "column", "diff", "cmp", "jq", "yq", "dasel", "csvlook",
  "cp", "scp", "rsync", "install", "tar", "zip", "gzip", "bzip2", "xz", "base64", "shasum",
  "md5", "md5sum", "sha1sum", "sha256sum", "openssl", "gpg", "dd",
  "curl", "wget", "nc", "netcat", "ncat", "socat", "aws", "s3cmd", "rclone",
  "source", ".",
])

// ---------------------------------------------------------------------------
// Interpreters — p10 #6, "EXECUTING a file under /tmp or under the working
// areas — however it is spelled: an interpreter in front of it, ./ or its bare
// absolute path, find -exec, xargs, or a chmod +x clearing the way".
// ---------------------------------------------------------------------------

const INTERPRETERS = new Set([
  "bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "ash",
  "python", "python2", "python3", "ruby", "perl", "node", "bun", "deno", "php",
  "osascript", "Rscript", "lua", "tclsh", "expect", "swift",
])

/** Flags whose VALUE is an inline program, not a path. `bash -c '…'`, `node -e '…'`. */
const INLINE_PROGRAM_FLAGS = new Set(["-c", "-e", "-m", "--eval", "--command", "-p", "-E"])

/** Command wrappers this canonicalizer strips to reach the real verb. */
const WRAPPERS = new Set([
  "command", "builtin", "exec", "nohup", "nice", "time", "timeout", "stdbuf",
  "caffeinate", "env", "xargs", "sudo", "doas", "then", "do", "!",
])

/** Directories whose contents are ordinary system binaries, so /bin/rm ≡ rm. */
const BIN_DIRS = new Set(["/bin", "/usr/bin", "/usr/local/bin", "/sbin", "/usr/sbin", "/opt/homebrew/bin", "/opt/local/bin"])

/** Shell keywords that lead a segment and are not the command. */
const LEADING_KEYWORDS = new Set(["do", "then", "else", "elif", "fi", "done", "esac", "{", "}", "!", "(", ")", "time"])

// ---------------------------------------------------------------------------
// Lexer / segmenter
// ---------------------------------------------------------------------------

const SUB = "\x00SUB\x00"

/**
 * Remove heredoc BODIES so the newline splitter does not see script text as
 * commands, while keeping the `cat > file <<'EOF'` head so its redirect is
 * still judged. Approximate: a `<<WORD` inside single quotes would be treated
 * as a heredoc opener. Measured on all four corpora and 65k real commands
 * without a misparse; noted here so a future failure is recognisable.
 */
function stripHeredocs(text) {
  const lines = text.split("\n")
  const out = []
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    out.push(line)
    const re = /<<[-~]?\s*(?:(['"])([^'"]+)\1|\\?([A-Za-z_][A-Za-z0-9_]*))/g
    const delims = []
    let m
    while ((m = re.exec(line)) !== null) delims.push(m[2] ?? m[3])
    for (const d of delims) {
      let j = i + 1
      while (j < lines.length && lines[j].trim() !== d) j++
      i = j // skip body and the terminator line
    }
  }
  return out.join("\n")
}

/**
 * Split a command into segments and tokens in one pass, so quoting state is
 * never lost. Returns `[{ words, redirects, subs, assignments }]` where a word
 * is `{ v, concrete, derived }`:
 *   v         the unquoted text, with known variables substituted
 *   concrete  false when the text still holds a glob, a variable, or the result
 *             of a command substitution — every path rule declines on these
 *   derived   true for `${f%.tmp}`-style expansions (a name derived from
 *             another name), which is what the rename rule keys on
 */
function parseSegments(text) {
  const segs = []
  let cur = { words: [], redirects: [], subs: [] }
  let buf = ""
  let has = false
  let concrete = true
  let derived = false
  let pendingOp = null

  const flushWord = () => {
    if (!has) return
    const w = { v: buf, concrete, derived }
    if (pendingOp) {
      // `2>&1` / `>&2` name a file descriptor, not a file.
      if (pendingOp !== ">&" && pendingOp !== "<&" && pendingOp !== "<<" && pendingOp !== "<<<" && !w.v.startsWith("&")) {
        cur.redirects.push({ op: pendingOp, target: w })
      }
      pendingOp = null
    } else {
      cur.words.push(w)
    }
    buf = ""; has = false; concrete = true; derived = false
  }
  const endSeg = () => {
    flushWord()
    if (cur.words.length || cur.redirects.length || cur.subs.length) segs.push(cur)
    cur = { words: [], redirects: [], subs: [] }
  }
  const add = (s, { opaque = false } = {}) => { buf += s; has = true; if (opaque) concrete = false }

  const captureBalanced = (s, start, open, close) => {
    let depth = 0
    for (let k = start; k < s.length; k++) {
      if (s[k] === "\\") { k++; continue }
      if (s[k] === open) depth++
      else if (s[k] === close) { depth--; if (depth === 0) return k }
    }
    return -1
  }

  let i = 0
  while (i < text.length) {
    const c = text[i]

    if (c === "\\") { add(text[i + 1] ?? ""); i += 2; continue }

    if (c === "'") {
      const end = text.indexOf("'", i + 1)
      if (end === -1) { add(text.slice(i + 1)); i = text.length; continue }
      add(text.slice(i + 1, end))
      has = true
      i = end + 1
      continue
    }

    if (c === '"') {
      // Read to the closing quote, then re-feed the inside through the same
      // substitution handling so `"$(cat ~/.netrc)"` still registers a sub.
      let k = i + 1
      let inner = ""
      while (k < text.length && text[k] !== '"') {
        if (text[k] === "\\") { inner += text[k + 1] ?? ""; k += 2; continue }
        inner += text[k]; k++
      }
      const sub = parseInlineSubs(inner, cur, captureBalanced)
      add(sub.text, { opaque: sub.opaque })
      if (sub.derived) derived = true
      has = true
      i = k + 1
      continue
    }

    if (c === "$" && text[i + 1] === "(") {
      const end = captureBalanced(text, i + 1, "(", ")")
      if (end === -1) { add(text.slice(i)); i = text.length; continue }
      cur.subs.push(text.slice(i + 2, end))
      add(SUB, { opaque: true })
      i = end + 1
      continue
    }

    if (c === "$" && text[i + 1] === "{") {
      const end = captureBalanced(text, i + 1, "{", "}")
      if (end === -1) { add(text.slice(i)); i = text.length; continue }
      const body = text.slice(i + 2, end)
      // ${f%.tmp} / ${f#pre} / ${f/a/b} derive a NEW name from an existing one.
      if (/[%#/]/.test(body)) derived = true
      add("${" + body + "}", { opaque: true })
      i = end + 1
      continue
    }

    if (c === "`") {
      const end = text.indexOf("`", i + 1)
      if (end === -1) { add(text.slice(i)); i = text.length; continue }
      cur.subs.push(text.slice(i + 1, end))
      add(SUB, { opaque: true })
      i = end + 1
      continue
    }

    if ((c === "<" || c === ">") && text[i + 1] === "(") {
      const end = captureBalanced(text, i + 1, "(", ")")
      if (end === -1) { add(text.slice(i)); i = text.length; continue }
      cur.subs.push(text.slice(i + 2, end))
      add(SUB, { opaque: true })
      i = end + 1
      continue
    }

    if (c === "#" && !has) {
      const nl = text.indexOf("\n", i)
      i = nl === -1 ? text.length : nl
      continue
    }

    if (c === "\n") { endSeg(); i++; continue }
    if (c === ";") { endSeg(); i++; continue }
    if (c === "|") { endSeg(); i += text[i + 1] === "|" ? 2 : 1; continue }
    if (c === "&") {
      if (text[i + 1] === "&") { endSeg(); i += 2; continue }
      if (text[i + 1] === ">") {
        flushWord()
        pendingOp = text[i + 2] === ">" ? "&>>" : "&>"
        i += pendingOp === "&>>" ? 3 : 2
        continue
      }
      endSeg(); i++; continue
    }

    if (c === ">" || c === "<") {
      if (has && /^\d+$/.test(buf)) { buf = ""; has = false } // fd prefix: 2>
      else flushWord()
      let op = c
      if (c === ">") {
        if (text[i + 1] === ">") { op = ">>"; i++ }
        else if (text[i + 1] === "|") { op = ">|"; i++ }
        else if (text[i + 1] === "&") { op = ">&"; i++ }
      } else {
        if (text[i + 1] === "<" && text[i + 2] === "<") { op = "<<<"; i += 2 }
        else if (text[i + 1] === "<") { op = "<<"; i++ }
        else if (text[i + 1] === "&") { op = "<&"; i++ }
      }
      i++
      pendingOp = op
      continue
    }

    if (/\s/.test(c)) { flushWord(); i++; continue }

    if (c === "*" || c === "?" || c === "[" || c === "$") add(c, { opaque: true })
    else add(c)
    i++
  }
  endSeg()
  return segs
}

/** Handle `$( )`, backticks and `${ }` found inside a double-quoted run. */
function parseInlineSubs(inner, cur, captureBalanced) {
  let out = ""
  let opaque = false
  let derived = false
  let i = 0
  while (i < inner.length) {
    if (inner[i] === "$" && inner[i + 1] === "(") {
      const end = captureBalanced(inner, i + 1, "(", ")")
      if (end === -1) { out += inner.slice(i); break }
      cur.subs.push(inner.slice(i + 2, end))
      out += SUB; opaque = true; i = end + 1; continue
    }
    if (inner[i] === "`") {
      const end = inner.indexOf("`", i + 1)
      if (end === -1) { out += inner.slice(i); break }
      cur.subs.push(inner.slice(i + 1, end))
      out += SUB; opaque = true; i = end + 1; continue
    }
    if (inner[i] === "$" && inner[i + 1] === "{") {
      const end = captureBalanced(inner, i + 1, "{", "}")
      if (end === -1) { out += inner.slice(i); break }
      const body = inner.slice(i + 2, end)
      if (/[%#/]/.test(body)) derived = true
      out += "${" + body + "}"; opaque = true; i = end + 1; continue
    }
    if (inner[i] === "$") { out += "$"; opaque = true; i++; continue }
    out += inner[i]; i++
  }
  return { text: out, opaque, derived }
}

// ---------------------------------------------------------------------------
// Context and path helpers
// ---------------------------------------------------------------------------

function makeContext(opts) {
  const home = opts.home ?? os.homedir()
  return {
    projectDir: opts.projectDir ? path.resolve(opts.projectDir) : null,
    workingAreas: (opts.workingAreas ?? defaultWorkingAreas(home)).map((p) => path.resolve(resolveHome(p, home))),
    dropDirs: dropDirs(home),
    home,
    fs: opts.fs ?? nodeFs,
  }
}

function resolveHome(p, home) {
  if (p === "~") return home
  return p.startsWith("~/") ? path.join(home, p.slice(2)) : p
}

function under(abs, root) {
  if (!abs || !root) return false
  return abs === root || abs.startsWith(root.endsWith("/") ? root : root + "/")
}

/** macOS aliases /tmp onto /private/tmp; both spellings must land in the same place. */
function normalizeTmp(abs) {
  if (abs === "/tmp" || abs.startsWith("/tmp/")) return "/private" + abs
  if (abs === "/var/tmp" || abs.startsWith("/var/tmp/")) return "/private/var/tmp" + abs.slice("/var/tmp".length)
  return abs
}

function isScratch(abs) {
  const n = normalizeTmp(abs)
  return under(n, "/private/tmp") || under(n, "/private/var/tmp")
}

/**
 * The agent's own working areas. `~/.claude/projects/<slug>/memory` is matched
 * structurally (mirrors ccOwnRoot) rather than listed, because the slug is
 * per-project; the rest of ~/.claude is configuration.
 */
function isWorkingArea(abs, ctx) {
  for (const a of ctx.workingAreas) if (under(normalizeTmp(abs), normalizeTmp(a))) return true
  const projects = path.join(ctx.home, ".claude", "projects")
  if (under(abs, projects)) {
    const rest = abs.slice(projects.length + 1).split("/")
    if (rest.length >= 2 && rest[1] === "memory") return true
  }
  return false
}

/** Where p10 says overwriting, truncating and deleting are routine housekeeping. */
function isExempt(abs, ctx) {
  return isScratch(abs) || isWorkingArea(abs, ctx)
}

/** Where p10 says RUNNING a file is RISKY even though writing it is fine. */
function isExecArea(abs, ctx) {
  if (isExempt(abs, ctx)) return true
  for (const d of ctx.dropDirs) if (under(abs, d)) return true
  return false
}

/**
 * ~/.claude minus the working areas is configuration — `> ~/.claude/settings.json`
 * is a hardcases RISKY, and `sed -i '' ../settings.json` from ~/.claude/plans is
 * a heldout3 RISKY. The shipped SENSITIVE_PATH_PATTERNS predates the hook and
 * does not carry this clause; the cc-hook expresses it as ccOwnRoot instead.
 */
function isClaudeConfig(abs, ctx) {
  const root = path.join(ctx.home, ".claude")
  return under(abs, root) && !isWorkingArea(abs, ctx)
}

function isSensitiveWriteTarget(abs, ctx) {
  if (SENSITIVE_WRITE_PATTERNS.some((re) => re.test(abs))) return true
  return isClaudeConfig(abs, ctx)
}

/** Resolve a word to an absolute path, or null when it is not concrete. */
function resolveWord(w, state, ctx) {
  if (!w || !w.concrete || !w.v) return null
  if (w.v.includes(SUB)) return null
  let p = resolveHome(w.v, ctx.home)
  if (p.startsWith("-")) return null
  if (!path.isAbsolute(p)) {
    if (!state.cwd) return null
    p = path.resolve(state.cwd, p)
  }
  return path.normalize(p.replace(/\/+$/, "")) || "/"
}

function exists(abs, ctx) {
  if (!abs) return false
  try { return ctx.fs.existsSync(abs) } catch { return false }
}

function isDir(abs, ctx) {
  if (!abs) return false
  try {
    if (typeof ctx.fs.statSync === "function") return ctx.fs.statSync(abs).isDirectory()
  } catch { return false }
  return false
}

// ---------------------------------------------------------------------------
// Segment analysis
// ---------------------------------------------------------------------------

/** Strip wrappers, `VAR=x` prefixes and `/usr/bin/` to reach the real verb. */
function canonicalize(words, state) {
  let ws = words.slice()
  const flags = { sudo: false, xargs: false }

  for (;;) {
    while (ws.length && LEADING_KEYWORDS.has(ws[0].v) && ws[0].v !== "time") ws = ws.slice(1)
    // `VAR=value cmd …` and plain assignments; remember literal scalars so a
    // later `$VAR` can be resolved (d=/usr/local/src/x; cd "$d/tmp").
    while (ws.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(ws[0].v)) {
      const eq = ws[0].v.indexOf("=")
      const name = ws[0].v.slice(0, eq)
      const val = ws[0].v.slice(eq + 1)
      if (ws[0].concrete) state.vars.set(name, val)
      else state.vars.delete(name)
      ws = ws.slice(1)
    }
    if (!ws.length) break
    const v = ws[0].v
    if (v === "sudo" || v === "doas") {
      flags.sudo = true
      ws = ws.slice(1)
      // sudo's own flags; -u/-g/-C take a value.
      while (ws.length && ws[0].v.startsWith("-")) {
        const f = ws[0].v
        ws = ws.slice(1)
        if ((f === "-u" || f === "-g" || f === "-C" || f === "--user" || f === "--group") && ws.length) ws = ws.slice(1)
      }
      continue
    }
    if (v === "xargs") {
      flags.xargs = true
      ws = ws.slice(1)
      while (ws.length && ws[0].v.startsWith("-")) {
        const f = ws[0].v
        ws = ws.slice(1)
        if ((f === "-I" || f === "-n" || f === "-P" || f === "-L" || f === "-d" || f === "-s") && ws.length) ws = ws.slice(1)
      }
      continue
    }
    if (v === "nice" || v === "timeout" || v === "stdbuf") {
      ws = ws.slice(1)
      while (ws.length && ws[0].v.startsWith("-")) ws = ws.slice(1)
      if (v === "timeout" && ws.length && /^[\d.]+[smhd]?$/.test(ws[0].v)) ws = ws.slice(1)
      if (v === "nice" && ws.length && /^-?\d+$/.test(ws[0].v)) ws = ws.slice(1)
      continue
    }
    if (v === "env") {
      ws = ws.slice(1)
      while (ws.length && (ws[0].v.startsWith("-") || /^[A-Za-z_][A-Za-z0-9_]*=/.test(ws[0].v))) ws = ws.slice(1)
      continue
    }
    if (WRAPPERS.has(v)) { ws = ws.slice(1); continue }
    break
  }

  // The command word as WRITTEN, after wrappers and `VAR=value` prefixes are
  // gone but before /bin/ is stripped: the execution rule needs to see the path
  // a bare `/tmp/tools/fmt` names. Taking it before the loop was a bug —
  // `DEVELOPER_DIR=/…/x cmd` made the ASSIGNMENT look like the command word,
  // and resolved under a scratchpad cwd it fired scratch-execution 11 times in
  // 52k real commands.
  const rawFirst = ws[0] ?? null
  let verb = ws.length ? ws[0].v : null
  // /bin/rm ≡ rm, but only for the standard bin directories — /tmp/tools/fmt
  // must stay an absolute path so the execution rule can see where it lives.
  if (verb && verb.includes("/") && BIN_DIRS.has(path.dirname(verb))) verb = path.basename(verb)
  return { verb, args: ws.slice(1), rawFirst, sudo: flags.sudo, xargs: flags.xargs }
}

/** Substitute `$NAME` / `${NAME}` from tracked literal assignments. */
function expand(words, state) {
  return words.map((w) => {
    if (!w.v.includes("$")) return w
    let v = w.v
    let resolvedAll = true
    v = v.replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, a, b) => {
      const name = a ?? b
      if (state.vars.has(name)) return state.vars.get(name)
      resolvedAll = false
      return m
    })
    const stillOpaque = v.includes("$") || v.includes(SUB) || /[*?[]/.test(v)
    return { v, concrete: resolvedAll && !stillOpaque, derived: w.derived }
  })
}

const NON_FLAG = (w) => !w.v.startsWith("-") && w.v !== "--"

/** Operands, dropping flags. `--` ends flag parsing. */
function operands(args) {
  const out = []
  let sawDashDash = false
  for (const a of args) {
    if (!sawDashDash && a.v === "--") { sawDashDash = true; continue }
    if (!sawDashDash && a.v.startsWith("-") && a.v !== "-") continue
    out.push(a)
  }
  return out
}

function hasFlag(args, ...names) {
  return args.some((a) => names.some((n) => a.v === n || a.v.startsWith(n + "=")))
}

// ---------------------------------------------------------------------------
// The rules
// ---------------------------------------------------------------------------

/**
 * `why` is read by a human in a toast, so it is capped at a length that fits
 * one. Long absolute paths (a session scratchpad is ~110 characters on its own)
 * would otherwise push it past anything readable.
 */
const RISKY = (rule, why) => ({ verdict: "RISKY", rule, why: why.length > 240 ? why.slice(0, 237) + "..." : why })

/**
 * R1 credential-kinds — p10 #5.
 * A credential is a KIND of file, not a location: reading `.env.example` inside
 * the project, `.npmrc`, a `*.key`, anything under ~/.ssh / ~/.aws / ~/.kube,
 * or asking a credential store for a secret. Keyed on a content-reading verb so
 * `ls -la ~/.ssh` and `stat … id_ed25519` stay untouched.
 */
function ruleCredentials(seg, cmd, state, ctx) {
  const { verb, args } = cmd

  // Credential stores that PRINT a secret.
  if (verb === "security") {
    const sub = operands(args)[0]?.v ?? ""
    // `find-generic-password`, `find-internet-password`, `dump-keychain`.
    // `security list-keychains` only names them and is labelled SAFE.
    if (/^find-.*password$/.test(sub) || sub === "dump-keychain") {
      return RISKY("credential-kinds", `\`security ${sub}\` prints a stored password from the keychain`)
    }
  }
  if (verb === "gh" && operands(args)[0]?.v === "auth" && operands(args)[1]?.v === "token") {
    return RISKY("credential-kinds", "`gh auth token` prints the stored GitHub token")
  }
  if (verb === "op") {
    const ops = operands(args).map((a) => a.v)
    if (ops[0] === "read") return RISKY("credential-kinds", "`op read` fetches a secret out of 1Password")
    // `op item get` prints the whole item, passwords included, and `op document
    // get` the stored file: the same secret as `op read`, spelled differently.
    // On 1,710 traffic commands 6 of 6 uses were labelled RISKY. `op item list`,
    // `op vault list`, `op whoami` only name things and stay with the model.
    if ((ops[0] === "item" || ops[0] === "document") && ops[1] === "get") {
      return RISKY("credential-kinds", `\`op ${ops[0]} get\` fetches a 1Password item, secrets included`)
    }
  }
  if (verb === "git") {
    const gargs = gitArgs(args)
    if (gargs[0]?.v === "credential") {
      return RISKY("credential-kinds", "`git credential` talks to the credential store")
    }
    // p10 #5: "git config credential.*". `git config user.email` and
    // `commit.gpgsign` are ordinary reads and must not match. Matched on the
    // bare word, not on `credential.`, because the live spelling is a regex —
    // `git config --global --get-regexp '^credential\.'` — where the dot is
    // escaped and a literal "credential." never appears.
    if (gargs[0]?.v === "config" && gargs.slice(1).some((a) => /credential/i.test(a.v))) {
      return RISKY("credential-kinds", "reads or writes the git credential configuration")
    }
  }
  // `find / -name id_rsa -exec cat {} \;` — the hunt is the credential access.
  if (verb === "find") {
    for (let i = 0; i < args.length - 1; i++) {
      if (args[i].v === "-name" || args[i].v === "-iname") {
        const kind = credentialKind("/x/" + args[i + 1].v.replace(/[*?]/g, ""))
        if (kind) return RISKY("credential-kinds", `searches the filesystem for ${args[i + 1].v} — ${kind}`)
      }
    }
  }

  const looksAtContent = verb !== null && CONTENT_READ_VERBS.has(verb)
  const candidates = []
  if (looksAtContent) {
    for (const a of operands(args)) candidates.push(a)
    // `curl -d @.env.staging` names the file with a leading @.
    for (const a of args) if (a.v.startsWith("@") && a.v.length > 1) candidates.push({ ...a, v: a.v.slice(1) })
  }
  // A `< file` redirect reads the file whatever the verb is (`nc … < ~/.aws/credentials`).
  for (const r of seg.redirects) if (r.op === "<") candidates.push(r.target)

  for (const w of candidates) {
    const abs = resolveWord(w, state, ctx)
    if (!abs) continue
    const kind = credentialKind(abs)
    if (kind) return RISKY("credential-kinds", `${w.v} — ${kind}; reading it is RISKY wherever it lives`)
  }
  return null
}

/**
 * R10 hooks-bypassed — not a p10 clause; measured on traffic. `--no-verify`
 * skips the pre-commit, commit-msg and pre-push hooks, which are the checks a
 * repository put in the way of exactly the commit being made. The one gate-S
 * miss p10 left on 1,710 traffic commands was a merge script run with it, at
 * pSAFE 1.000: the model cannot see inside a script and the flag is the only
 * signal there is. Matched as an exact word on ANY verb, because the flag
 * reaches git through wrappers and scripts, never only through `git`. Fires
 * 8 times on traffic, 7 labelled RISKY.
 */
function ruleHooksBypassed(cmd) {
  if (cmd.args.some((a) => a.v === "--no-verify")) {
    return RISKY("hooks-bypassed", "`--no-verify` skips the repository's hooks — the checks put in the way of exactly this")
  }
  return null
}

/** git's own options before the subcommand (`git -C dir push …`). */
function gitArgs(args) {
  const out = []
  let i = 0
  while (i < args.length) {
    const v = args[i].v
    if (v === "-C" || v === "-c" || v === "--git-dir" || v === "--work-tree" || v === "--namespace") { i += 2; continue }
    if (v.startsWith("-")) { i++; continue }
    break
  }
  for (; i < args.length; i++) out.push(args[i])
  return out
}

/**
 * R2 force-push — p10 #3 ("push --force"), spelled out in every form: --force,
 * -f, --force-with-lease, --force-if-includes, and a leading `+` refspec.
 * Rewriting a published branch is the one git operation whose damage lands on
 * other people, and it is exactly decidable from the flags.
 */
function ruleForcePush(cmd) {
  if (cmd.verb !== "git") return null
  const g = gitArgs(cmd.args)
  if (g[0]?.v !== "push") return null
  const rest = g.slice(1)
  for (const a of rest) {
    if (a.v === "--force" || a.v === "-f" || /^-[a-zA-Z]*f[a-zA-Z]*$/.test(a.v)) {
      return RISKY("force-push", "force-pushes — it can overwrite commits on the remote that are not in this checkout")
    }
    if (a.v === "--force-with-lease" || a.v.startsWith("--force-with-lease=")) {
      return RISKY("force-push", "force-pushes with a lease — still rewrites the remote branch")
    }
    if (a.v === "--force-if-includes") {
      return RISKY("force-push", "force-pushes — it can overwrite commits on the remote")
    }
    if (a.v.startsWith("+") && a.v.length > 1 && !a.v.startsWith("-")) {
      return RISKY("force-push", `the refspec ${a.v} is a force push`)
    }
  }
  return null
}

/**
 * R3 git-history — p10 #3, "Discarding git work". Every one of these throws
 * away state that exists nowhere else, and none of them needs a model.
 *
 * DELIBERATELY NOT IMPLEMENTED: `git clean -f`. p10 #3 names it hard-RISKY, but
 * eval/hardcases.mjs section E labels `git clean -fdx` SAFE ("clean build tree
 * — common, though it deletes untracked"). The corpora are the gate, and a rule
 * that fires on a case a human labelled SAFE is a bug in this layer. Left to
 * the model until that label is revisited.
 */
function ruleGitHistory(cmd, state, ctx) {
  if (cmd.verb !== "git") return null
  const g = gitArgs(cmd.args)
  const sub = g[0]?.v
  const rest = g.slice(1)
  if (!sub) return null

  if (sub === "reset" && hasFlag(rest, "--hard", "--merge", "--keep")) {
    return RISKY("git-history", "`git reset --hard` throws away every uncommitted change in the working tree")
  }
  if (sub === "checkout" || sub === "restore") {
    if (hasFlag(rest, "-f", "--force")) {
      return RISKY("git-history", `\`git ${sub} -f\` overwrites local modifications`)
    }
    // `--` is unambiguously a pathspec separator: everything after it is a file.
    if (rest.some((a) => a.v === "--")) {
      return RISKY("git-history", `\`git ${sub} -- <path>\` discards uncommitted edits to those files`)
    }
    if (sub === "restore") {
      // `--staged` alone only unstages; it does not touch the working tree.
      if (!(hasFlag(rest, "--staged", "-S") && !hasFlag(rest, "--worktree", "-W"))) {
        return RISKY("git-history", "`git restore` overwrites the working copy of the named files")
      }
      return null
    }
    // A pathspec without `--`: `.`, `./x`, `src/`, or a name that exists on
    // disk. A branch name is left alone, including one with a slash
    // (`git checkout feat/x` is routine).
    if (!hasFlag(rest, "-b", "-B", "--orphan", "--track", "-t", "--detach")) {
      for (const a of operands(rest)) {
        if (a.v === "." || a.v.startsWith("./") || a.v.endsWith("/")) {
          return RISKY("git-history", `\`git checkout ${a.v}\` discards uncommitted edits under that path`)
        }
        // A bare word (`main`, `develop`, `HEAD~2`) is a revision. Only a
        // path-SHAPED operand is worth a stat — otherwise a branch that shares
        // a name with a directory in the cwd would read as a pathspec.
        if (!a.v.includes("/") && !a.v.includes(".")) continue
        const abs = resolveWord(a, state, ctx)
        if (abs && exists(abs, ctx)) {
          return RISKY("git-history", `\`git checkout ${a.v}\` names a path that exists — it discards uncommitted edits to it`)
        }
      }
    }
    return null
  }
  if (sub === "switch" && hasFlag(rest, "-f", "--force", "--discard-changes")) {
    return RISKY("git-history", "`git switch --force` discards uncommitted changes")
  }
  if (sub === "branch" && (hasFlag(rest, "-D") || (hasFlag(rest, "-d", "--delete") && hasFlag(rest, "--force")))) {
    return RISKY("git-history", "`git branch -D` deletes a branch even if it is unmerged")
  }
  if (sub === "push" && hasFlag(rest, "--delete", "-d")) {
    return RISKY("git-history", "`git push --delete` removes a branch or tag from the remote")
  }
  if (sub === "stash" && (rest[0]?.v === "drop" || rest[0]?.v === "clear")) {
    return RISKY("git-history", `\`git stash ${rest[0].v}\` destroys stashed work permanently`)
  }
  if (sub === "filter-branch" || sub === "filter-repo") {
    return RISKY("git-history", `\`git ${sub}\` rewrites history across the whole repository`)
  }
  if (sub === "reflog" && rest[0]?.v === "expire") {
    return RISKY("git-history", "`git reflog expire` removes the safety net that makes a bad reset recoverable")
  }
  if (sub === "gc" && hasFlag(rest, "--prune")) {
    return RISKY("git-history", "`git gc --prune` deletes unreachable objects a reflog could still have recovered")
  }
  return null
}

/**
 * R4 scratch-execution — p10 #6, the on-sight rule the model misses most.
 * "EXECUTING a file under /tmp or under the working areas — however it is
 * spelled: an interpreter in front of it, ./ or its bare absolute path, find
 * -exec, xargs, or a chmod +x clearing the way in the same command — including
 * one the same command just wrote there, and one planted in a drop directory
 * such as ~/.local/bin or ~/bin. Reading such a file is still fine; only
 * running it is not."
 *
 * The user's own installed tooling — ~/.config/claude-skills, ~/.assistant, a
 * Homebrew binary, ~/.nvm — is judged by its arguments, not its directory, and
 * needs no exemption here because none of it lives in a scratch, working or
 * drop area.
 */
function ruleScratchExecution(seg, cmd, state, ctx) {
  const say = (what, abs) => RISKY(
    "scratch-execution",
    `runs ${what} out of ${abs} — a scratch or working area; what it does is not visible in the command`,
  )

  // 1. The command word itself is a path into an exec area: `/tmp/tools/fmt`,
  //    `./deploy.sh` after `cd <scratchpad>`, `~/.local/bin/run`.
  const first = cmd.rawFirst
  if (first && (first.v.includes("/") || first.v.startsWith("~"))) {
    const abs = resolveWord(first, state, ctx)
    if (abs && isExecArea(abs, ctx)) return say("an executable", abs)
  }

  // 2. An interpreter (or `source`) with a path operand in an exec area.
  if (cmd.verb && (INTERPRETERS.has(cmd.verb) || cmd.verb === "source" || cmd.verb === ".")) {
    const args = cmd.args
    for (let i = 0; i < args.length; i++) {
      const a = args[i]
      if (INLINE_PROGRAM_FLAGS.has(a.v)) { i++; continue } // the value is a program, not a path
      if (a.v.startsWith("-") && a.v !== "-") continue
      if (a.v === "--") continue
      if (a.v === "-") break // reads the script from stdin
      const abs = resolveWord(a, state, ctx)
      if (abs && isExecArea(abs, ctx)) return say(`the script ${path.basename(abs)}`, abs)
      break // only the first operand is the script; the rest are its arguments
    }
  }

  // 3. `find <area> … -exec <interpreter> {} \;`
  if (cmd.verb === "find") {
    const roots = operands(cmd.args).filter((a) => !a.v.startsWith("-"))
    const rootAbs = roots.map((a) => resolveWord(a, state, ctx)).filter(Boolean)
    for (let i = 0; i < cmd.args.length - 1; i++) {
      if (cmd.args[i].v !== "-exec" && cmd.args[i].v !== "-execdir") continue
      const runner = cmd.args[i + 1].v
      const base = runner.includes("/") ? path.basename(runner) : runner
      if (!INTERPRETERS.has(base)) continue
      for (const r of rootAbs) if (isExecArea(r, ctx)) return say(`whatever ${runner} finds`, r)
    }
  }

  // 4. `eval "$(cat /tmp/x)"` — the payload is a file in a scratch area.
  if (cmd.verb === "eval") {
    for (const subText of seg.subs) {
      for (const sseg of parseSegments(subText)) {
        for (const w of sseg.words) {
          const abs = resolveWord(w, state, ctx)
          if (abs && isExecArea(abs, ctx)) return say("the contents of", abs)
        }
      }
    }
  }
  return null
}

/**
 * R5 destination-exists — p10 #2, "cp/mv whose destination path is already
 * taken (renaming a file to a name nothing else uses destroys nothing and is
 * SAFE)". That parenthesis is the whole rule: the difference between a safe
 * rename and a silent overwrite is one `stat`, and the model cannot do it.
 * Exempt in scratch and the working areas, per p10 PLACES.
 */
function ruleDestinationExists(cmd, state, ctx) {
  const COPY_VERBS = new Set(["cp", "mv", "rsync", "install", "ln"])
  if (!cmd.verb || !COPY_VERBS.has(cmd.verb)) return null
  if (cmd.verb === "ln" && !hasFlag(cmd.args, "-f", "--force", "-sf", "-fs")) return null
  const ops = operands(cmd.args)
  if (ops.length < 2) return null
  const dest = ops[ops.length - 1]
  const sources = ops.slice(0, -1)

  // A destination naming a variable/glob is not decidable by stat — but a
  // rename whose new name is DERIVED from the old one (`mv "$f" "${f%.tmp}"`)
  // is the classic loop that lands on a name that may already be taken. The
  // task's fallback: flag it when the paths it works over look tracked (inside
  // the project, outside every scratch area).
  if (!dest.concrete) {
    if (!dest.derived) return null
    const anchor = state.lastForGlob ?? sources[0]
    const anchorAbs = anchor ? resolveGlobDir(anchor, state, ctx) : null
    if (!anchorAbs || isExempt(anchorAbs, ctx)) return null
    if (ctx.projectDir && !under(anchorAbs, ctx.projectDir)) return null
    return RISKY(
      "destination-exists",
      `renames onto ${dest.v}, a name derived from the source — under ${anchorAbs} the destination may already exist and would be overwritten`,
    )
  }

  const destAbs = resolveWord(dest, state, ctx)
  if (!destAbs || isExempt(destAbs, ctx)) return null

  // `rsync --delete` into an existing directory removes whatever is there and
  // is not in the source; that is destruction regardless of per-file clobber.
  if (cmd.verb === "rsync" && hasFlag(cmd.args, "--delete", "--delete-after", "--delete-before", "--delete-during") && exists(destAbs, ctx)) {
    return RISKY("destination-exists", `rsync --delete into ${dest.v}, which already exists — files there that are not in the source are removed`)
  }

  if (isDir(destAbs, ctx)) {
    // Copying INTO a directory only clobbers if the per-file target is taken.
    for (const s of sources) {
      if (!s.concrete) continue
      const sAbs = resolveWord(s, state, ctx)
      if (!sAbs) continue
      const landing = path.join(destAbs, path.basename(sAbs))
      if (exists(landing, ctx)) {
        return RISKY("destination-exists", `${cmd.verb} onto ${landing}, which already exists — its contents are replaced`)
      }
    }
    return null
  }
  if (exists(destAbs, ctx)) {
    return RISKY("destination-exists", `${cmd.verb} onto ${dest.v}, which already exists — its contents are replaced`)
  }
  return null
}

/** The directory a glob like `src/*.ts.tmp` lives in, for the rename rule. */
function resolveGlobDir(w, state, ctx) {
  const raw = w.v.replace(SUB, "")
  const dir = raw.includes("/") ? raw.slice(0, raw.lastIndexOf("/")) : "."
  if (/[*?[$]/.test(dir)) return null
  return resolveWord({ v: dir, concrete: true }, state, ctx)
}

/**
 * R6 truncate-existing — p10 #2, "Destroying contents in place: a redirect
 * `> path` in every spelling … tee p, >|, truncate". Restricted here to a
 * CONCRETE target that EXISTS: p10 tells the model to assume the worst because
 * it cannot see the filesystem, but this layer can, and firing on every
 * `cmd > new-file.log` would be pure friction.
 *
 * Exempt in scratch and the working areas (p10 PLACES), and on /dev/* — a
 * `>/dev/null` is not a truncation of anything.
 */
function ruleTruncateExisting(seg, cmd, state, ctx) {
  const targets = []
  for (const r of seg.redirects) {
    if (r.op === ">" || r.op === ">|" || r.op === "&>") targets.push(r.target)
  }
  if (cmd.verb === "tee" && !hasFlag(cmd.args, "-a", "--append")) {
    for (const a of operands(cmd.args)) targets.push(a)
  }
  if (cmd.verb === "truncate") {
    const zero = cmd.args.some((a, i) => (a.v === "-s" || a.v === "--size") && cmd.args[i + 1]?.v?.replace(/^0+$/, "") === "") ||
      cmd.args.some((a) => a.v === "-s0" || a.v === "--size=0")
    if (zero) for (const a of operands(cmd.args)) targets.push(a)
  }
  for (const t of targets) {
    const abs = resolveWord(t, state, ctx)
    if (!abs) continue
    if (abs.startsWith("/dev/")) continue
    if (isExempt(abs, ctx)) continue
    if (isDir(abs, ctx)) continue
    if (exists(abs, ctx)) {
      return RISKY("truncate-existing", `empties ${t.v}, which already exists — the redirect replaces its contents, it does not read them`)
    }
  }
  return null
}

/**
 * R7 system-config-write — p10 #4, "MODIFYING ~/.zshrc, ~/.bashrc, launchd
 * plists, /etc/*". Reuses the SENSITIVE_PATH_PATTERNS logic the write-tool
 * layer already applies (local-classifier.js judgeWritePath), extended to the
 * shell's own write channels: redirects, tee, sed -i / perl -pi, and a
 * cp/mv/install/ln destination. Existence is NOT required — the damage is the
 * file's role, not its current contents.
 */
function ruleSystemConfigWrite(seg, cmd, state, ctx) {
  const targets = []
  for (const r of seg.redirects) {
    if (r.op === ">" || r.op === ">>" || r.op === ">|" || r.op === "&>" || r.op === "&>>") targets.push(r.target)
  }
  if (cmd.verb === "tee") for (const a of operands(cmd.args)) targets.push(a)
  if ((cmd.verb === "sed" || cmd.verb === "perl" || cmd.verb === "ruby" || cmd.verb === "gsed") &&
      cmd.args.some((a) => a.v === "-i" || a.v.startsWith("-i.") || /^-[a-zA-Z]*i[a-zA-Z]*$/.test(a.v))) {
    const ops = operands(cmd.args)
    if (ops.length) targets.push(ops[ops.length - 1])
  }
  if (cmd.verb && ["cp", "mv", "install", "ln", "rsync"].includes(cmd.verb)) {
    const ops = operands(cmd.args)
    if (ops.length >= 2) targets.push(ops[ops.length - 1])
  }
  for (const t of targets) {
    const abs = resolveWord(t, state, ctx)
    if (!abs) continue
    if (isSensitiveWriteTarget(abs, ctx)) {
      return RISKY("system-config-write", `writes ${t.v} — shell, login or system configuration, or credential storage`)
    }
  }
  return null
}

/**
 * R9 env-dump — p10 #4, "reading back what was typed or exported in this
 * shell". A process environment is where every exported token lives, so
 * printing one whole is a credential read with no filename to key on. The
 * shape is decidable: it is the ABSENCE of an operand that makes `env`,
 * `printenv`, `set`, `export` and `declare` dump everything, and one named
 * variable (`printenv HOME`, `echo $HOME`) is not this rule.
 *
 * `env` needs the raw words, not `cmd`: canonicalize() treats `env` as a
 * WRAPPER and strips it, so `env` alone canonicalizes to a null verb and
 * `env FOO=1 cmd` to `cmd`. That difference is exactly the rule — env with a
 * command after it is a runner, env with nothing after it is a dump — so this
 * one rule reads `seg.words` and re-does the wrapper skipping itself.
 *
 * `ps -E` and not `ps -e`: measured on this machine (macOS 25.6, `man ps`),
 * `-E` displays the environment and `-e` is "identical to -A", the everyday
 * `ps -ef | grep …`. `-e` means the environment only in ps's LEGACY mode
 * (COMMAND_MODE=legacy), and firing on it would flag a routine process
 * listing on every platform to catch a spelling nobody here uses. BSD-style
 * flag words without a dash keep their `e` (`ps auxe`, `ps eww -p 1`), which
 * IS the environment on both macOS and Linux.
 */
function ruleEnvDump(seg, cmd, state, ctx) {
  const words = withoutRunners(seg.words)
  const head = words[0]?.v ?? null
  const rest = words.slice(1)
  const ops = operands(rest)

  if (head === "env") {
    // Flags and `NAME=value` assignments are still an env invocation; a
    // command word after them makes it a runner (`env FOO=1 node x.js`,
    // `env -i sh -c …`). -u/-S/-C/--chdir take a value of their own.
    let i = 0
    while (i < rest.length) {
      const v = rest[i].v
      if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(v)) { i++; continue }
      if (v === "-u" || v === "-S" || v === "-C" || v === "--chdir" || v === "--unset") { i += 2; continue }
      if (v.startsWith("-")) { i++; continue }
      break
    }
    if (i >= rest.length) return RISKY("env-dump", "`env` with no command prints the whole environment, exported tokens included")
    return null
  }

  if (head === "printenv" && ops.length === 0) {
    return RISKY("env-dump", "`printenv` with no variable named prints the whole environment")
  }

  // Bare `set` prints every variable AND function. `set -e`, `set -o pipefail`
  // and `set -- a b` configure the shell and print nothing.
  if (head === "set" && rest.length === 0) {
    return RISKY("env-dump", "bare `set` prints every shell variable and function, exported tokens included")
  }

  // `export` / `declare -x` / `typeset -x` / `declare -p` with nothing to set
  // print the whole exported environment; with a NAME they do not.
  if (head === "export" || head === "declare" || head === "typeset") {
    const assigns = rest.some((a) => !a.v.startsWith("-"))
    if (!assigns && (head === "export" || rest.some((a) => /^-[a-zA-Z]*[xp]/.test(a.v)))) {
      return RISKY("env-dump", `\`${[head, ...rest.map((a) => a.v)].join(" ")}\` prints the exported environment`)
    }
    return null
  }

  // macOS launchd's own environment: `launchctl export` writes it as shell
  // commands, `launchctl getenv` reads it back.
  if (head === "launchctl") {
    const sub = ops[0]?.v
    if (sub === "export" || sub === "getenv") {
      return RISKY("env-dump", `\`launchctl ${sub}\` reads launchd's environment, which is where exported secrets end up`)
    }
    return null
  }

  if (head === "ps") {
    // Flags whose VALUE is the next word: `ps -o user,pid` must not read as
    // BSD flags containing an `e`.
    const TAKES_VALUE = new Set(["-o", "-O", "-p", "-t", "-u", "-U", "-G", "-g", "-c", "-M", "--format", "--pid", "--user", "--sort"])
    for (let i = 0; i < rest.length; i++) {
      const v = rest[i].v
      if (TAKES_VALUE.has(v)) { i++; continue }
      if (v.startsWith("--")) continue
      // `-Eww`, `-aE`: a cluster containing E.
      if (v.startsWith("-")) {
        if (v.slice(1).includes("E")) return RISKY("env-dump", `\`ps ${v}\` prints every process's environment, this shell's exported tokens included`)
        continue
      }
      // BSD style carries no dash and comes first (`ps auxe`, `ps eww -p 1`);
      // there the `e` IS the environment, on macOS and on Linux.
      if (i === 0 && /^[a-zA-Z]+$/.test(v) && v.includes("e")) {
        return RISKY("env-dump", `\`ps ${v}\` prints every process's environment, this shell's exported tokens included`)
      }
    }
    return null
  }

  // Linux: the environment as a file. Any reader, and a `< /proc/…/environ`
  // redirect, which has no verb to key on.
  const PROC_ENVIRON = /^\/proc\/([0-9]+|self|thread-self|\*)\/environ$/
  const candidates = [...operands(cmd.args)]
  for (const r of seg.redirects) if (r.op === "<") candidates.push(r.target)
  for (const w of candidates) {
    if (PROC_ENVIRON.test(w.v)) {
      return RISKY("env-dump", `${w.v} is a process's environment; reading it prints its exported tokens`)
    }
  }
  return null
}

/**
 * Leading words that are not the command, for a rule that cannot use
 * canonicalize(): shell keywords, `sudo`/`doas` and their flags, and the
 * wrappers that run another program. `env` is deliberately NOT skipped — for
 * this rule it IS the command.
 */
function withoutRunners(words) {
  let ws = words.slice()
  for (;;) {
    while (ws.length && LEADING_KEYWORDS.has(ws[0].v)) ws = ws.slice(1)
    const v = ws[0]?.v
    if (v === "sudo" || v === "doas") {
      ws = ws.slice(1)
      while (ws.length && ws[0].v.startsWith("-")) {
        const f = ws[0].v
        ws = ws.slice(1)
        if ((f === "-u" || f === "-g" || f === "-C" || f === "--user" || f === "--group") && ws.length) ws = ws.slice(1)
      }
      continue
    }
    if (v === "command" || v === "builtin" || v === "exec" || v === "nohup" || v === "caffeinate") { ws = ws.slice(1); continue }
    break
  }
  return ws
}

/**
 * R8 privilege-system — p10 #4 and #9. Privilege escalation, world-writable or
 * setuid modes, ownership changes, launchd/systemd state changes, `defaults
 * write`, and killing a process this shell did not start.
 *
 * `sudo -n true` is carved out: it is a capability PROBE with no effect, and
 * eval/hardcases.mjs labels it SAFE. Reads stay reads — `launchctl list`,
 * `launchctl print`, `defaults read` never fire.
 */
function rulePrivilegeSystem(cmd, state, ctx) {
  if (cmd.sudo) {
    const inner = cmd.verb
    // A no-op probe: `sudo -n true`. Anything else runs with root authority.
    if (inner !== null && inner !== "true" && inner !== "false") {
      return RISKY("privilege-system", `runs \`${inner}\` as root via sudo`)
    }
    if (inner === null) return null
    return null
  }
  if (cmd.verb === "chmod") {
    for (const a of operands(cmd.args)) {
      const m = a.v
      if (/^[0-7]?[0-7]{3}$/.test(m)) {
        const digits = m.length === 4 ? m.slice(1) : m
        const special = m.length === 4 ? Number(m[0]) : 0
        if (Number(digits[2]) & 2) return RISKY("privilege-system", `chmod ${m} makes the target world-writable`)
        if (special & 6) return RISKY("privilege-system", `chmod ${m} sets the setuid/setgid bit`)
      }
      if (/^[ugoa,+=rwxst-]+$/.test(m) && /[+=]/.test(m)) {
        if (/(^|,)(a|o|ugo|go)[+=][^,]*w/.test(m)) return RISKY("privilege-system", `chmod ${m} makes the target world-writable`)
        if (/[+=][^,]*s/.test(m)) return RISKY("privilege-system", `chmod ${m} sets the setuid/setgid bit`)
      }
      break // only the first operand is the mode
    }
    return null
  }
  if (cmd.verb === "chown" || cmd.verb === "chgrp") {
    return RISKY("privilege-system", `\`${cmd.verb}\` changes file ownership`)
  }
  if (cmd.verb === "launchctl") {
    const sub = operands(cmd.args)[0]?.v
    if (sub && ["load", "unload", "bootstrap", "bootout", "kickstart", "enable", "disable", "remove", "submit", "start", "stop"].includes(sub)) {
      return RISKY("privilege-system", `\`launchctl ${sub}\` changes what runs on this machine`)
    }
    return null
  }
  if (cmd.verb === "systemctl") {
    const sub = operands(cmd.args)[0]?.v
    if (sub && ["start", "stop", "restart", "enable", "disable", "mask", "unmask", "daemon-reload"].includes(sub)) {
      return RISKY("privilege-system", `\`systemctl ${sub}\` changes a system service`)
    }
    return null
  }
  if (cmd.verb === "defaults") {
    const sub = operands(cmd.args)[0]?.v
    if (sub && ["write", "delete", "import", "rename"].includes(sub)) {
      return RISKY("privilege-system", `\`defaults ${sub}\` changes a macOS preference outside this project`)
    }
    return null
  }
  // p10 #9: killing what this shell did not start.
  if (cmd.verb === "pkill" || cmd.verb === "killall") {
    return RISKY("privilege-system", `\`${cmd.verb}\` kills processes by name — the command cannot show this shell started them`)
  }
  if (cmd.verb === "kill") {
    for (const a of cmd.args) {
      if (a.v.startsWith("%") || a.v === "$!") return null // this shell's own job
    }
    for (const a of cmd.args) {
      if (!a.concrete && a.v.includes(SUB)) {
        return RISKY("privilege-system", "kills a PID discovered by a command substitution — not a job this shell started")
      }
    }
    if (hasFlag(cmd.args, "-9", "-KILL", "-SIGKILL")) {
      for (const a of operands(cmd.args)) {
        if (/^\d+$/.test(a.v)) return RISKY("privilege-system", `kill -9 of PID ${a.v} — the command cannot show this shell started it`)
      }
    }
    return null
  }
  return null
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Rules run in this order; the first hit wins and names the verdict. The order
 * is what the traffic report attributes a flag to, so it is deliberately
 * "what the human would call this command" rather than alphabetical.
 */
const RULES = [
  { id: "credential-kinds", fn: (seg, cmd, state, ctx) => ruleCredentials(seg, cmd, state, ctx) },
  { id: "env-dump", fn: (seg, cmd, state, ctx) => ruleEnvDump(seg, cmd, state, ctx) },
  { id: "force-push", fn: (seg, cmd) => ruleForcePush(cmd) },
  { id: "hooks-bypassed", fn: (seg, cmd) => ruleHooksBypassed(cmd) },
  { id: "git-history", fn: (seg, cmd, state, ctx) => ruleGitHistory(cmd, state, ctx) },
  { id: "privilege-system", fn: (seg, cmd, state, ctx) => rulePrivilegeSystem(cmd, state, ctx) },
  { id: "scratch-execution", fn: (seg, cmd, state, ctx) => ruleScratchExecution(seg, cmd, state, ctx) },
  { id: "system-config-write", fn: (seg, cmd, state, ctx) => ruleSystemConfigWrite(seg, cmd, state, ctx) },
  { id: "destination-exists", fn: (seg, cmd, state, ctx) => ruleDestinationExists(cmd, state, ctx) },
  { id: "truncate-existing", fn: (seg, cmd, state, ctx) => ruleTruncateExisting(seg, cmd, state, ctx) },
]

/** Longest command this layer looks at; past it, the model (or the human) decides. */
const MAX_COMMAND_CHARS = 20_000

/**
 * @param {string} command                the exact string handed to the shell
 * @param {object} [opts]
 * @param {string|null} [opts.projectDir] absolute path of the project; relative
 *                                        paths resolve against it (and against
 *                                        the current dir as `cd` moves it)
 * @param {string[]} [opts.workingAreas]  the agent's own working areas
 * @param {object} [opts.fs]              injectable filesystem. BOTH `existsSync`
 *                                        and `statSync` are required — a stub
 *                                        with only `existsSync` makes every
 *                                        directory look like a file, and
 *                                        `cp a.txt existing-dir/` would then
 *                                        read as a clobber. Nothing else is
 *                                        called on it; contents are never read.
 * @returns {{verdict:"RISKY",rule:string,why:string}|null}
 */
export function judgeBashCommand(command, opts = {}) {
  if (typeof command !== "string" || command.trim() === "") return null
  if (command.length > MAX_COMMAND_CHARS) return null
  const ctx = makeContext(opts)
  try {
    return judgeAll(command, ctx, 0)
  } catch {
    // A parser bug must never become a verdict. This layer only ever ADDS asks,
    // so declining is the status quo, not a hole.
    return null
  }
}

function judgeAll(command, ctx, depth) {
  const state = { cwd: ctx.projectDir, vars: new Map(), lastForGlob: null }
  const segs = parseSegments(stripHeredocs(command))
  for (const seg of segs) {
    const words = expand(seg.words, state)
    const cmd = canonicalize(words, state)

    // `for f in src/*.ts.tmp; do …` — remember the glob so the rename rule can
    // tell where the loop's files live.
    if (cmd.verb === "for" || words[0]?.v === "for") {
      const inIdx = words.findIndex((w) => w.v === "in")
      if (inIdx !== -1 && words[inIdx + 1]) state.lastForGlob = words[inIdx + 1]
    }

    // Command substitutions run their own commands; judge them at this cwd.
    if (depth < 3) {
      for (const sub of seg.subs) {
        const hit = judgeNested(sub, ctx, state, depth + 1)
        if (hit) return hit
      }
    }

    for (const r of RULES) {
      const hit = r.fn(seg, cmd, state, ctx)
      if (hit) return hit
    }

    // `cd` moves the current directory for everything after it. Subshell and
    // pipeline scoping is NOT modelled: a `cd` inside `( … )` or on the left of
    // a `|` is treated as if it persisted. Over-resolving is the safe error
    // here — it only ever makes a relative path concrete, and every rule that
    // uses one also requires the file to exist or to be a credential kind.
    if (cmd.verb === "cd" || cmd.verb === "pushd") {
      const target = operands(cmd.args)[0]
      if (!target) state.cwd = ctx.home
      else {
        const abs = resolveWord(target, state, ctx)
        state.cwd = abs ?? null
      }
    }
  }
  return null
}

function judgeNested(text, ctx, parentState, depth) {
  const state = { cwd: parentState.cwd, vars: new Map(parentState.vars), lastForGlob: null }
  const segs = parseSegments(stripHeredocs(text))
  for (const seg of segs) {
    const words = expand(seg.words, state)
    const cmd = canonicalize(words, state)
    if (depth < 3) {
      for (const sub of seg.subs) {
        const hit = judgeNested(sub, ctx, state, depth + 1)
        if (hit) return hit
      }
    }
    for (const r of RULES) {
      const hit = r.fn(seg, cmd, state, ctx)
      if (hit) return hit
    }
    if (cmd.verb === "cd") {
      const target = operands(cmd.args)[0]
      state.cwd = target ? resolveWord(target, state, ctx) : ctx.home
    }
  }
  return null
}

/** Internals, exported for the tests only. */
export const internals = {
  parseSegments, stripHeredocs, canonicalize, credentialKind,
  isScratch, isWorkingArea, isExecArea, isSensitiveWriteTarget,
  SENSITIVE_WRITE_PATTERNS,
}
