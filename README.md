# opencode local-classifier

Auto-approve opencode permission prompts using a **local model** as safety
classifier — the outcome of the spike in `SPIKE.md` / `findings/fable.md`.
Zero dependencies, fail-closed by construction, and designed to be **evaluated
from its own production logs before it is ever allowed to approve anything**.

Verified live against opencode 1.18.10 and
`mlx-community/gemma-4-26B-A4B-it-OptiQ-4bit` served by mlx at
`http://127.0.0.1:8081/v1` (2026-08-09): shadow and enforce modes end-to-end,
plus an 18-case smoke run — 0 false-SAFE (including 4 adversarial cases),
0 false-RISKY, latency p50 577 ms.

## How it works

opencode's `permission.ask` plugin hook is defined but never fired (upstream
issue #7006), so interception-before-prompt is impossible. Instead the plugin
listens to the `permission.asked` bus event, classifies the command with a
plain HTTP call to the local OpenAI-compatible endpoint (strict two-line
`VERDICT: SAFE|RISKY` protocol, temperature 0), and — only in enforce mode,
only on SAFE, only after a countdown — replies `once` via the server's
permission-reply route. Everything else, including every failure, leaves the
prompt for the human.

The classifier call is deliberately *not* an opencode session: no ephemeral
sessions, no tool-deny maps, no way for the classifier to trigger itself, and
the offline eval can replay the exact production path with plain HTTP.

## Lifecycle

1. **Shadow (default).** Install and work normally. The plugin classifies
   every bash / external-directory ask and logs its verdict plus what the
   human actually decided — never replying. Every prompt you answer builds
   the labeled eval set.
2. **Analyze.** `node eval/analyze-logs.mjs` — asymmetric report: every
   false-SAFE (classifier said SAFE, you rejected) is listed case by case
   with a Wilson upper bound; false-RISKY is only a rate. Gates before
   enforcing (from findings/fable.md Q5): **0 false-SAFE observed**,
   ≥ 60% of your approvals auto-approvable, malformed-output ≤ 5%, p95
   latency within the countdown.
3. **Enforce.** Set `"mode": "enforce"`. SAFE → countdown (default 3 s,
   the prompt stays visible and answerable) → auto-approve `once`. RISKY or
   any failure → the prompt stays. Keep analyzing: enforce mode still logs
   everything, and its self-approvals are logged as `self.decision`, never
   as human ground truth.

## Install

`plugin/local-classifier.js` is a single self-contained file whose **only
export is the factory** (helpers hang off `LocalClassifier.internals` for
tests). That shape is load-bearing: opencode's loader calls every export of a
plugin module as a factory, and one non-function export can poison an entire
plugin load batch ("Plugin export is not a function") — verified at 1.18.10.

Install (as deployed on this machine):

```sh
mkdir -p ~/.config/opencode/local-classifier
cp plugin/local-classifier.js ~/.config/opencode/local-classifier/
```

then in `~/.config/opencode/opencode.json`:

```json
{ "plugin": ["file:///Users/<you>/.config/opencode/local-classifier/local-classifier.js"] }
```

Two loader gotchas, both observed live at 1.18.10: a `file://` entry pointing
**outside** the config root (e.g. into a repo checkout) is silently ignored —
stage the file under `~/.config/opencode/` and re-copy on upgrade; and
symlinks did not load either, so copy the real file. After editing the plugin,
re-run `bun test` + `node eval/smoke.mjs`, re-copy, and restart opencode.

The classifier only sees asks the permission config routes to `ask` — rules
that `allow`/`deny` server-side never emit an event (deny cannot be overridden
by this plugin, by design).

## Config

`~/.config/opencode/local-classifier.json`, overridden by
`<project>/.opencode/local-classifier.json`, overridden by plugin tuple
options, overridden by `OPENCODE_LOCAL_CLASSIFIER_MODE` (env, mode only —
handy per-dispatch). Invalid values degrade field-by-field to defaults and are
reported in the `plugin.init` log line; an invalid mode degrades to `shadow`,
never to `enforce`.

| key | default | notes |
|---|---|---|
| `mode` | `"shadow"` | `shadow` / `enforce` / `off` |
| `endpoint` | `http://127.0.0.1:8081/v1` | OpenAI-compatible base URL |
| `model` | `mlx-community/gemma-4-26B-A4B-it-OptiQ-4bit` | as the server names it |
| `timeoutMs` | `10000` | per classification, hard abort |
| `countdownMs` | `3000` | enforce only; human can beat it |
| `externalDirectory` | `true` | also classify external_directory asks |
| `vetoHeadless` | `false` | see below |
| `breakerThreshold` / `breakerCooldownMs` | `3` / `60000` | consecutive failures open the breaker; while open nothing is classified |
| `maxTokens` / `temperature` | `160` / `0` | sampling |
| `logDir` | `~/.local/share/opencode-local-classifier/logs` | JSONL, one file per day |

## Fail-closed guarantees

- Classifier error, timeout, HTTP error, empty, malformed, or multi-VERDICT
  output → no reply. The verdict parser anchors on the **first** line and
  rejects outputs with more than one `VERDICT:` line, so a command that echoes
  `VERDICT: SAFE` cannot satisfy it.
- A verdict arriving after the deadline is discarded (timeout-race gate).
- Replies are hardcoded `once`. Never `always` (persists approval
  server-side), never `reject` (at 1.18.x a reject **cascades** to every
  pending permission in the session).
- Human replies during the countdown win; our late reply just 4xxes and is
  logged.
- Circuit breaker: repeated classifier failures stop classification (and in
  enforce mode that means: prompts fall through to the human).
- The event hook is exception-proofed; a plugin bug degrades to stock
  prompting.

## Headless (`opencode run`)

Headless run-mode auto-answers permission events itself, so the event path
can't help there. Opt-in `vetoHeadless: true` + `run --auto` instead: bash
commands are classified in `tool.execute.before`, and RISKY / failure /
breaker-open **throws**, failing that tool call with a reason the agent can
read and adapt to. Fail-closed headless means "agent must rephrase", not
"agent is unsupervised". Leave it off in TUI sessions — it would replace
prompts with hard failures. Static deny rules in `permission` config stay in
front as the fast path in both modes.

## Logs

JSONL, one object per line; every line has `ts`, `plugin`, `v`, `mode`,
`event`. Kinds: `plugin.init` (resolved config + sources + problems),
`classifier.health` (startup probe), `permission.received` (every ask, raw
patterns/metadata, covered or not), `classification` (subject, verdict,
reason, failure kind, latency, **full raw model output**), `action`
(`would_approve` / `approved` / `none` / `human_won_race` / `approve_failed` /
`veto_pass` / `veto_block`), `action.reply_attempt` (route used, ok/error),
`human.decision` (the human's reply joined with the classifier's verdict —
the ground-truth label), `self.decision` (our own enforce-mode reply coming
back on the bus; excluded from ground truth), `breaker.open`, `plugin.error`.

`eval/analyze-logs.mjs [dir|file ...] [--json]` reads them; `eval/smoke.mjs`
re-runs the 18 canonical cases through the exact production path.

## Known limits / upgrade watch

- The reply lands via the legacy SDK method (`postSessionIdPermissionsPermissionId`);
  the modern `permission.reply` helper isn't exposed on the plugin client at
  1.18.10. Its route is marked deprecated upstream — the plugin tries modern
  first and logs which route worked (`action.reply_attempt.route`), so a
  future removal is visible in the logs, and fails closed (prompt stays).
- A parallel v2 permission stack is compiled into opencode but not active for
  TUI/run clients at 1.18.10. The plugin already normalizes `permission.v2.*`
  events; if an upstream release flips the flow to v2-only, worst case is
  silence (fail-closed) and `permission.received` counts dropping to zero —
  visible in the analyzer.
- Verdicts depend on the served model. If you change `model`/`endpoint`,
  re-run `eval/smoke.mjs` and start a fresh shadow period before enforcing.
