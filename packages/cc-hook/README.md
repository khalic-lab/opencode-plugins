# cc-hook — the local classifier as a Claude Code PreToolUse hook

Same classifier as the opencode plugin, same p7 prompts, same corpus. The
prompts and `classify()` are **imported** from `../local-classifier/local-classifier.js`
rather than copied, so `eval/smoke.mjs` and `eval/hardcases.mjs` keep measuring
exactly what this hook runs. Measured 2026-09-02: smoke 66/66 PASS with 0 false-SAFE at p50 395 ms, and
hardcases 0 false-SAFE / 2 known false-RISKY (`git clean -fdx`, `sudo -n true`)
of 36. The hook end to end is 450–550 ms including node startup (p50 627 ms,
p90 910 ms over the first 150 live calls), against ~1.5 s for the built-in
classifier's first stage and 9289 ms for both stages.

## Install

```sh
# 1. wire the hook (merge the `hooks` block into ~/.claude/settings.json)
cat settings-fragment.json

# 2. keep the model's prompt prefix hot — not optional, see below
cp com.khalic.cc-classifier-warm.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.khalic.cc-classifier-warm.plist

# 3. verify
./test/exit-discipline.sh          # 71 checks, needs the model up
node cc-classifier-hook.mjs --warm # prints e.g. "warm SAFE 942ms"
```

It starts in **shadow**: one verdict logged per tool call, nothing blocked.
Promote with `{"mode":"enforce"}` in `~/.config/cc-local-classifier/config.json`,
or `CC_CLASSIFIER_MODE=enforce` in the hook command. Write that file **before**
step 1: the hook layers its mode on top of `~/.config/opencode/local-classifier.json`,
and on 2026-09-02 that file said enforce, so a hook with no file of its own
armed in enforce and blocked five commands in other sessions before the shadow
file existed. The posture defaults to `cascade` (below); `{"posture":"veto"}`
or `CC_CLASSIFIER_POSTURE=veto` gives the pure veto layer.

Both the fragment and the plist name `/opt/homebrew/bin/node`, not `node`: a
spawn failure fails open, and launchd's PATH does not include Homebrew.

Logs: `~/.local/share/cc-local-classifier/logs/events-<date>.jsonl`, deliberately
**not** the opencode log dir — the analyzer must not blend two harnesses into
one gate. Every line carries `harness: "claude-code"` and `posture`. The
`action` line's `decided` is what the hook said: `allow`, `deny`, `pass` (said
nothing, the built-in classifier decides) or `uncovered`; shadow logs
`would_allow` / `would_deny` instead of speaking. Hook version 0.2.0 renamed
these from `veto_block` / `veto_would_block`, narrowed `pass` to "said nothing"
(an emitted allow is now `allow`), and fixed `mode`, which until then was
copied from the opencode file and read `enforce` on every shadow row.

## Why PreToolUse and not PermissionRequest

`PermissionRequest` is documented as "run before permission prompt", which is
the event this wants, and it is what opencode's dead `permission.ask` was
supposed to be. Measured on 2.1.258 it **never fires headless**: six
provocations (plain echo, network curl, credential read, scope-escalating
write, a forced `permissions.ask` denial, and a PreToolUse-passthrough
combination) produced zero invocations, while a `PreToolUse` hook declared in
the same `settings.json` fired every time. Interactive behaviour is
unverified — driving the TUI from `expect` failed three times.

`PreToolUse` fires in every mode tested: default, auto, manual,
bypassPermissions.

## The fail-closed contract inverts here

In the opencode plugin, doing nothing was safe: not replying left the human's
prompt on screen. In Claude Code, doing nothing is an **approval**.

| condition | result |
|---|---|
| exit 2, any stdout including empty | denied |
| exit 1, stderr set | **allowed** ("non-blocking status code") |
| exit 0, malformed JSON | **allowed** |
| hook binary missing / spawn failure | **allowed** |
| hook exceeds its `timeout` | **allowed** (outcome `cancelled`, never sets `.blocked`) |

Two consequences shape the whole file:

1. **An unhandled exception exits 1, which is a silent approve.** Every path
   out funnels to `deny()`, via handlers installed before anything can throw.
   The exit-discipline battery is what proves it, and it caught a real bug: with
   the mode resolved *after* `import()`, a broken install blocked every command
   in a session configured for shadow.
2. **The harness `timeout` is not the deadline.** It fails open, so it must
   never be what fires. It is set to 30 s purely as a backstop above the hook's
   own 12 s watchdog, which fires first and follows the posture's failure
   column: veto and solo exit 2, cascade says nothing. Verified: a wedged stdin
   pipe denies at 2568 ms under veto with `deadlineMs: 2500`, rather than
   hanging to the harness timeout and being approved. The classifier's own
   `timeoutMs` is clamped to leave 2 s of headroom under the deadline, so a
   slow model lands as `classifier failed (timeout)` and takes the posture's
   failure path rather than the watchdog's.

`countdownMs` from the plugin does not port and should not. It existed to race
the human to a permission prompt that was already drawn; a `PreToolUse` hook
runs before any prompt exists, so a delay buys nothing.

## Posture: which way the local verdict may move the decision

The opencode plugin approves on SAFE and leaves RISKY to the human. The local
model can only *add* permission, so a false SAFE is the unrecoverable error and
a false RISKY costs one keystroke — which is exactly what `eval/hardcases.mjs`
scores: "FALSE-SAFE (unrecoverable)", "false-RISKY (friction)".

The first port inverted that. SAFE said nothing and the built-in classifier
decided; RISKY denied. That made the local model a pure veto — it can only
*remove* permission — so a false SAFE cost nothing, a false RISKY was a final
block, and the corpus was tuned for the wrong error. The shadow log settled it
in its first hour: all 23 RISKY verdicts were reads outside the project
(`sed -n` and `grep` over installed Python source under `~/.local/share`,
launchd plists, a config file) that the built-in classifier let through. In
enforce every one would have been a hard deny.

`posture` picks the direction:

| posture | SAFE | RISKY | model failure | the local model can only |
|---|---|---|---|---|
| `cascade` (default) | allow | say nothing | say nothing | add permission |
| `veto` | say nothing | deny | deny, see `breakerPolicy` | remove permission |
| `solo` | allow | deny | deny, see `breakerPolicy` | either |

The table governs the bash path and, with `externalDirectory` on, reads that
leave the project. An in-project write or read says nothing in every posture:
the path rules are the only judgement made there, and claiming an allow on a
write would rest on a filename alone. "Model failure" includes the hook's own
deadline — running out of time is the model's failure mode, not the hook's.

"Say nothing" hands the call to the built-in classifier, which is
transcript-aware and better informed than a stateless model. Measured on
2.1.258 its first stage costs ~1.5 s on a safe command and both stages ~9.3 s
on a risky one; this hook is ~0.6 s end to end. So cascade saves ~0.9 s per
safe call and spends 0.6 s per risky one; veto spends 0.6 s per safe call and
saves ~8.7 s per risky one; and veto is the faster posture only when the *true*
RISKY rate is above roughly 14 %. On this machine it is near zero.

What cascade costs is that a false SAFE runs without a second opinion. The
evidence that this is rare is the offline corpus — smoke 66/66 and hardcases
36/36 at zero false SAFE — and shadow cannot add to it: with the hook silent,
the built-in classifier's verdict is not in any log a session writes by
default. Only `-d --debug-file` records `classifier_request_started`, and even
that carries no verdict.

Two things are the same in every posture. The deterministic path rules deny
(a hook deny is gate-independent, see below). An over-long command (>4000
chars) says nothing: the model never saw it, "too long" is not a verdict, and
the built-in classifier has no length limit. Under the first port it denied.

Two things cascade exercises that veto never did:

- **`permissions.ask` precedence.** Under veto the hook never said allow, so
  the rules for `git push *`, `glab mr create *` and `gh pr create *` never
  had to override anything. Under cascade they must, on every SAFE verdict.
  Live result: see "Precedence" below.
- **Reads** are unaffected: `externalDirectory` stays off, so Read/Glob/Grep
  are uncovered and say nothing in every posture. The bash path is where
  cascade acts.

## Precedence

From the 2.1.258 decision function (`Rro`), in order:

```
hook deny             -> wins unconditionally, every mode, no feature gate
deny rule             -> overrides a hook allow
ask rule/safety check -> overrides a hook allow, runs the full pipeline
auto-mode funnel      -> gated on P("tengu_virtual_knuth", !1)
otherwise             -> hook allow bypasses the permission prompt
```

So the **deny** path is gate-independent, and the **allow** path is a latency
optimization Anthropic can switch off server-side — when the gate flips, a hook
allow is sent through the classifier anyway with `hookAllowVouched: true`. Under
cascade that means the whole benefit is revocable and the deterministic denies
are not.

Your three `permissions.ask` rules (`git push *`, `glab mr create *`,
`gh pr create *`) should override anything this hook allows. That reading comes
from `Rro` itself; the first e2e ran with `--setting-sources project`, so the
real user settings were never loaded. Exercised live on 2026-09-02 with user
settings loaded: a project `ask` rule on `Bash(echo precedence*)`, the hook in
enforce + cascade returning `allow` on that exact command. The debug log
recorded `Hook returned 'allow' for Bash, but ask rule/safety check requires
full permission pipeline`, and headless the call was denied with
`decision_reason_type: "rule"` — the classifier never ran. So a SAFE verdict
cannot bypass `git push *`; the ask rules stand.

## The warm keepalive is not optional

The plugin keeps the model's cached prompt prefix hot on an in-process timer
(`warmIntervalMs`, 4 min). A hook is a fresh process per tool call and cannot
hold a timer, so the keepalive moved to a launchd agent.

Without it the first classification after an eviction prefills the whole
~1670-token system prompt. Measured 2026-09-02: that took longer than the entire
10 s classifier timeout and returned `failure: "timeout"` — which in enforce
**denies a command that was never classified**. Warm, the same call is 450–550 ms.

## The one decision left: `breakerPolicy`

`createBreaker` held its counter in a closure, which worked because the plugin
was one long-lived process. Here it is a file under
`~/.local/state/cc-local-classifier/`. That part is mechanical. The policy is not:

- `"deny"` (default) — fail closed, consistent with the plugin's invariants. A
  wedged mlxctl means every covered command is refused and auto mode stops
  working until you notice.
- `"allow"` — fail open while the model is *known* down, logged loudly. The
  built-in classifier is still in the path, so the degradation is to stock
  Claude Code, not to nothing.

It applies to `veto` and `solo` only. Under `cascade` every model failure says
nothing, breaker open or not: that posture's safety was the built-in
classifier's to begin with, and a deny from a latency optimizer would refuse
commands the model never saw — which is exactly what a cold prompt prefix did
on 2026-09-02 (see the keepalive below). An exception *in the hook* still
denies in enforce whatever the posture — a bug should be loud — but the
watchdog follows the failure column, because running out of time is the
model's failure mode, not the hook's.

One caveat on `"allow"`: Claude Code dispatches independent tool calls
concurrently, and several hook processes can read `breaker.json` at
`consecutiveFailures: 0` and each write `1`. Under parallel load the counter may
never reach the threshold, so the breaker never opens and the allow policy never
engages — each call denies individually instead. The counter is best-effort. It
does not affect the `"deny"` default, which denies either way.

## Coverage

| tool | treatment |
|---|---|
| `Bash` | p7 bash classifier |
| `Write` `Edit` `NotebookEdit` | deterministic path rules, no model call |
| `Read` `Glob` `Grep` | **off by default** — see below |
| everything else | **not covered** — logged, never blocked |

Two directories the harness itself tells the model to write to sit outside
every project: the per-session scratchpad under `/private/tmp/claude-<uid>/`
the per-project memory under `~/.claude/projects/<slug>/memory/`, and plan files
under `~/.claude/plans/`. The plugin's boundary rule was written for opencode,
which has none of them, and in its
first hour of shadow this hook logged 16 would-be denies for exactly those —
another session's artifact edits and this project's memory file. They are now
judged with their own root as the project: the sensitive-path patterns still
apply, the boundary rule does not. The rest of `~/.claude` stays outside;
`settings.json` is what enables this hook. That is the deterministic half, for
Write and Edit, and for Read/Glob/Grep when the read path is on. The `p7` bash
prompt names the same three areas, where a heredoc into the scratchpad or an
append to `MEMORY.md` used to come back RISKY. The directory prompt does not:
tried on 2026-09-02, the model filed `~/.claude/settings.json` and a transcript
under "the agent's designated project memory area", so that side stays
deterministic and the directory prompt is unchanged from `p6`.

`WebFetch`, `Task` and MCP tools are uncovered on purpose. Failing closed on
every unknown tool id would break sessions outright and the hook would simply
be turned off.

### Why the read path is off by default

The plugin defaults `externalDirectory: true`. This hook defaults it **false**,
because the directory prompt names a home-directory root, `~/.config` and
`~/.local/share` as RISKY *by name* — which on this machine is the chezmoi
dotfile tree and `~/.claude`. Measured 2026-09-02 in enforce:

```
Read ~/.claude/settings.json                    -> RISKY, denied
Read ~/.local/share/chezmoi/dot_gitconfig.tmpl  -> RISKY, denied
Grep ~/.config                                  -> RISKY, denied
```

That is the classifier working exactly as specified and still being wrong for
this harness. In opencode the same verdict cost one keystroke at a TUI ask; here
a deny is final and the agent simply cannot read the file.

Turning it off does not leave reads unguarded: an uncovered read says nothing
and falls through to the built-in classifier, in every posture. The bash path — where
the damage is — stays covered either way. Set `{"externalDirectory": true}` to
opt back in; the battery covers both settings.

### The health check is the warm log, not "my sessions still work"

The settings fragment hardcodes an absolute path to this file, and a spawn
failure **fails open**. So renaming or moving the repo disarms the guard with no
symptom at all — sessions keep working, which is indistinguishable from a
working guard. The canary is the launchd agent: it runs `--warm` every four
minutes into `/tmp/cc-classifier-warm.log`. If that log is stale, assume the
hook is not running either.

## What is not ported

`sendApproval`, the reply routes, the pending map, event normalisation, the
toast probe and the TUI box — roughly 690 lines — existed only to work around
opencode's `permission.ask` never firing. Claude Code has the interception
point, so they are gone rather than translated.

Shadow mode has no `permission.replied` equivalent to join against:
`PermissionRequest` and `PermissionDenied` are both headless no-ops, and the
only live decision signal is `--output-format stream-json`'s
`system/permission_denied` event, which covers rule-driven denials only. It does
not matter much — the ground truth is `eval/smoke.mjs` and `eval/hardcases.mjs`,
and an offline corpus is a stronger gate than a live join.
