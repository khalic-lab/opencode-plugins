# omp-local-classifier

A local-model safety classifier in front of Oh My Pi's tool calls. It shares one
prompt and one decision core with the opencode plugin in
`packages/local-classifier` rather than copying them.

## Why it is a veto and not an approver

opencode asks the human and lets a plugin answer the prompt, so there the
classifier auto-**approves** and its fallback is "leave the prompt up". omp
resolves approval inside its tool wrapper from tier + policy + mode, and its
`tool_approval_requested` / `tool_approval_resolved` events are pure `emit`
whose return value is discarded. No extension can answer an omp prompt.

What an extension can do is `tool_call`, which fires *before* the approval gate
and which omp awaits. So here the classifier is a veto over `approvalMode:
yolo`: SAFE proceeds silently, RISKY blocks or asks.

The inversion removes most of the opencode plugin's machinery instead of
porting it. There is no pending map, no countdown, no reply race, no "once"
vs "always", and no reply-intent ordering — the decision is in-band. Two
fail-closed invariants moved into the runtime: `emitToolCall` turns both a
handler throw and a handler timeout into `{block: true}`, so a crash or a hang
in this extension cannot become silent consent.

## Install

```bash
omp install /usr/local/src/khalic-lab/opencode-automode-spike/packages/omp-extension
```

Or for one run, from the package directory:

```bash
omp -e ./omp-local-classifier.js
```

## Modes

| Mode | Behaviour |
| --- | --- |
| `off` | Nothing is classified. |
| `shadow` (default) | Classify, log, never act. |
| `enforce` | SAFE proceeds. RISKY or any failure takes `riskyAction`. |

Config is read from `~/.omp/agent/extensions/omp-local-classifier/config.json`
(trusted) and `<project>/.omp/local-classifier.json` (untrusted — may only
lower the mode and set the few allowed keys). `OMP_LOCAL_CLASSIFIER_MODE`
overrides both. Validation, trust rules and field defaults are the shared
resolver's, reached by translating its two opencode paths onto omp's.

Host-specific keys beyond the shared set:

- `riskyAction`: `"block"` (default) or `"confirm"`.
- `pathRules`: `false` (default). Applies the deterministic path rules — no
  model — to write/edit. See "what does not carry over". **Everything in the
  next section is dormant until you turn this on**, because the path rules are
  what produce the objection there is anything to ask about.
- `extraRoots`: `[]`. Folders that count as inside the project even when the
  session is elsewhere.
- `outsideProjectAction`: `"deny"` (default) or `"ask"`. What a write does when
  its only problem is landing outside the project.

The last two are read from the trusted user file only. A project file cannot
declare its own root, which would let a cloned repository widen the boundary
that is there to contain it.

## Approving a folder

A write can fail the path rules for two different reasons, and they are not
treated alike.

If the target is sensitive — credentials, SSH keys, shell or system config,
anything that runs on its own — it is refused, and no setting changes that. A
folder you have approved does not unlock a sensitive path inside it, and that
case never reaches a prompt at all.

If the only problem is that the target sits outside the session's project, that
is a boundary, and a boundary is yours to move. With `outsideProjectAction:
"ask"` you get a prompt naming the folder, which is the enclosing git repository
when there is one and the file's own directory otherwise. Approve it and the
write goes through and the folder is written to
`~/.omp/agent/extensions/omp-local-classifier/remembered-roots.json`, so the
next write there is silent — this session and every later one. Decline it, or
have no UI to be asked in, and it is refused.

A folder that could not be stored is never offered, so you cannot be asked the
same question forever. That is the same rule the config file uses: `/`, your
home directory, and the system directories are rejected outright rather than
quietly narrowed. The state file is re-checked on every read, so hand-editing an
over-broad entry into it does not work either.

Asking spends the handler budget described below, and 30 seconds is not long for
a human, so raise `extensionHandlers.toolCallTimeoutMs` before relying on this.

## Shadow means something different here

In opencode, shadow captured the human's decision from `permission.replied` and
filed it beside our verdict — that is what made the logs a labeled eval set.
Under omp's default `approvalMode: yolo` there is no human decision to capture,
so shadow would log verdicts against no ground truth.

To keep the methodology, run shadow with `tools.approvalMode: write`. Exec-tier
calls still prompt, this extension subscribes to `tool_approval_resolved`, and
the human's answer is logged next to our verdict keyed by `toolCallId`.

`/classifier` reports whether that is actually happening, counted from human
answers observed rather than read from config: `ExtensionContext` exposes no
`settings`, so `tools.approvalMode` is not reachable from an extension, and a
line that guessed it would report "unlabeled" even when the mode was set
correctly — the exact misconfiguration the line exists to catch.

## The 30-second cap

Every `tool_call` handler is bounded by `extensionHandlers.toolCallTimeoutMs`
(default 30000). Classification fits easily — measured 565–684 ms to the verdict
line against the local model on 2026-09-03. A confirm dialog waiting on a human
does not, and blowing the cap surfaces as a block with an "extension timed out"
reason rather than a prompt. So `riskyAction: "confirm"` requires raising that
setting first; any finite positive value is accepted. `"block"` is the default
precisely so the confirm path is opt-in after the cap is raised.

## What carries over, and what does not

**Carries over: the bash subject.** opencode sends `metadata.command`, the exact
string handed to the shell. omp's `tool_call` event carries `input.command`,
verified by probe at omp 18.1.5 to be exactly `{"command":"echo probe-ok"}` for
`echo probe-ok`. Same bytes, so `PROMPT_VERSION` and the existing shadow corpus
stay valid for bash and the two hosts' verdicts may be pooled. A test asserts
this rather than trusting it, because `normalizeToolEventInput` sits in the path.

Both hosts write to the same log directory by default, which is what makes one
pooled corpus possible — so every line this extension writes is stamped
`host: "omp"`. Without that the analyzer cannot separate them.

**Does not carry over: the directory half.** opencode's `external_directory`
permission hands over the exact filepath *and* the `dirname + "/*"` glob the
approval would grant, and `DIRECTORY_SYSTEM_PROMPT` is written for that two-line
subject — it tells the model the list "may contain … a directory pattern ending
in `/*`". omp has no such permission and so no glob to send, which makes a bare
path off-distribution for a prompt describing something that is not there. That
is a silent accuracy loss rather than an error, so v1 sends write/edit inputs to
the model **never**, under any setting, and `subjectFor` returns null for them.

What those tools do get, when `pathRules` is on, is the deterministic half —
`judgeWritePath` for sensitive paths and writes outside the project — which
needs no model and therefore holds even when the classifier is down. Giving the
directory half a model back means a new prompt version and its own shadow run.

## Status

End-to-end verified in shadow against the local model: two bash calls
classified SAFE at 684 ms and 565 ms to the verdict line, `contradicted: false`,
subjects byte-identical to the commands.

Not yet verified: whether `ctx.ui.confirm` renders and resolves from inside a
`tool_call` handler in the interactive TUI, rather than deadlocking against the
render loop. Both paths that ask — `riskyAction: "confirm"` and
`outsideProjectAction: "ask"` — depend on it, and both are off by default, so
nothing rests on it until it is proven. With no UI, confirm resolves false in
0 ms (probed at 18.1.5), so headless refuses rather than allows.

To check by hand, run `omp -e ./omp-local-classifier.js` with `mode: "enforce"`,
`pathRules: true` and `outsideProjectAction: "ask"`, ask for a write into a
repository outside the session, and see whether a dialog appears.

## Next

Shadow for a while, run `eval/analyze-logs.mjs` over the pooled corpus filtered
to `host: "omp"`, and only then consider `enforce`.
