# smart-approve reviewed against our fail-closed invariants

`mentalfl0w/smart-approve` (npm `smart-approve@2.6.0`, MIT, single maintainer,
32 commits) is the only third-party omp package that escalates a model verdict
to a human instead of hard-blocking. Reviewed at HEAD on 2026-09-03:
`src/gate.ts` (259 lines), `src/policy.ts` (76), `src/bash-tool.ts` (99), with
`src/config.ts` for defaults.

It is architecturally closer to our design than pi-automode is. It is not
invariant-clean, and two of the gaps would matter if we adopted it.

## The invariants

Invariants 3 and 4 are opencode's reply semantics — "once" not "always", and the
pending-entry race. smart-approve decides in-band like our omp extension, so
neither has a counterpart and neither is assessed.

| # | Invariant | Verdict |
| --- | --- | --- |
| 1 | Classifier error/timeout/non-200/empty/malformed → never approve | **Violated in auto mode by default** |
| 2 | A verdict arriving after the deadline is discarded | **Not implemented** |
| 4b | No approval without a durable audit line | **Violated** |
| 5 | Circuit breaker after N consecutive failures | **Absent** |
| 6 | A bug degrades to stock prompting, never a crash or an approval | Holds, by a different route |

## 1. Failure can approve, in auto mode with stock config

`gate.ts:191-208` wraps the model call in try/catch, logs, and leaves `aiResult`
null. What happens next depends on the mode.

Interactive mode is correct and is exactly our posture: the dialog renders
`t.analysisUnavailable` and the human decides (`gate.ts:229-233`). A classifier
failure costs one keystroke, never an approval.

Auto mode routes to `policy.decide(null, denyTier)`, which falls through to
`fallback()` (`policy.ts:66`). With `autoFallback: "block"` that blocks. The
default is `autoFallback: "regex"` (`config.ts:58`), so a command whose regex
behaviors did **not** hit the deny tier returns
`{verdict: "allow", reason: "fallback-regex"}` — a total classifier failure
producing an approval. That is invariant 1 inverted.

The exposure is bounded, and bounded specifically away from us: `mode` defaults
to `"interactive"` (`config.ts:56`), and `autoInHeadless` defaults to false so
subagents block outright rather than deciding. Interactive is the whole reason we
looked at this package — escalation to a human is the behaviour pi-automode
lacks — so the fail-open branch sits in the one configuration we would never run.
It still matters for anyone who flips to auto mode for the latency win and
inherits fail-open without setting `autoFallback: "block"`, and nothing in the
config warns them. But as an objection to *us* adopting it, this is the weakest
of the three.

A subtler case in the same function: `policy.ts:64` allows whenever
`recommend === "allow" || risk !== null`. A response where `recommend` is
unparseable garbage but `risk` parses as `"low"` is accepted. Our `parseVerdict`
rejects malformed output as a whole; this accepts a partial parse. The
contradiction rule above it (`risk high + recommend allow → block`) shows the
author thought about conflicting signals, so this reads as an oversight rather
than a decision.

## 2. No deadline, so no late-verdict gate

There is no per-call timeout in the decision path and nothing that discards a
verdict arriving after one. `modelInvoker.analyze` receives the tool's
`AbortSignal`, and `gate.ts:211` checks `signal?.aborted` after analysis — but
that covers user interruption, not a model answering past its own deadline.

Our invariant 2 exists because a partial pre-abort stream had contained
`VERDICT: SAFE`. The risk profile genuinely differs here: nothing races this
decision, because `execute()` runs outside the 30-second handler cap. The real
cost is the other direction — with no timeout, a wedged model hangs the tool call
until the user interrupts.

## 4b. Approvals do not depend on the audit line

`logger.log(...)` is fire-and-forget throughout; its return value is never read,
and every approval path proceeds regardless of whether the write succeeded. Our
plugin gates the approval on `wrote` and re-checks after the countdown. Adopting
this means running an auto-approver with no guarantee that what it approved was
recorded.

## 5. No circuit breaker

Nothing tracks consecutive failures. Every dangerous command re-attempts the
model, so a wedged local server costs the full analysis latency on every call,
indefinitely. This is the exact failure our cc-hook hit and answered with a
breaker, a doubling cooldown and a busy probe. On a shared single-generation mlx
server it is not theoretical.

## 6. Crash safety holds, by a different route

Only the model call is wrapped. `analyzeCommand`, `contextGatherer.gather`,
`allowList.isAllowed`, `policy.decide` and `confirmWithRemember` are not, so a
throw in any of them escapes `execute()`. Because the gate *is* the registered
tool, that surfaces as a failed tool call — the command does not run. So it
degrades closed, satisfying the invariant's intent.

The cost differs from ours: a throw in the behavior analyzer kills bash for the
session rather than degrading to unclassified-but-working bash. Our `tool_call`
veto degrades to "no classification"; this degrades to "no bash".

## What it does better than us

**It escapes the 30-second cap properly.** Registering a tool named `bash` and
delegating through `ctx.invokeTool` (`bash-tool.ts:89-97`) inherits shell path
resolution, env hardening, PTY and output truncation from the native tool, and
puts the model call and the dialog inside `execute()` where no handler budget
applies. My earlier objection — that shadowing bash means reimplementing it —
was wrong; delegation is what makes it cheap. This is the credible v2 for our
`riskyAction: "confirm"` path.

**Ordering is right.** Hard-block is checked before the allowlist
(`gate.ts:163`), with the stated reason that allowlist entries can predate a rule
upgrade or be hand-edited. Behaviour analysis runs before any model call, so a
command with no dangerous behaviour never pays for one.

**Interruption is handled at both ends.** `gate.ts:211` and `gate.ts:246` check
`aborted` before deciding and again after approval but before executing. The
second check is the one that is easy to miss.

## Two smaller things

`bash-tool.ts:40` says "Analysis subject = the cd-stripped command", but
`extractSubject` returns `p.command` verbatim. The code is right — judging what
actually runs is our principle too — and the comment is wrong; only `resolveCwd`
strips the prefix. A future change trusting that comment would break the very
fidelity the code has.

The shadow tool declares `approval: "exec"` (`gate.ts:130`). Under
`approvalMode: yolo` that is correct and the gate is the only control. Under
`write` or `always-ask` the user gets omp's own exec prompt *and* smart-approve's
dialog for the same call.

## Conclusion

Do not adopt as-is, but the reasons rank differently than the table suggests.

The unconditional blockers are 4b and 5: there is no audit gate on approvals and
no circuit breaker, in every mode and under every config. Those are the two we
would have to add before trusting it, and they are the two our own code learned
the hard way.

Invariant 1 is the loudest failure and the least relevant to us, because it lives
only in auto mode and we would run interactive. It is one config key from closed
(`autoFallback: "block"`), and the partial-parse hole at `policy.ts:64` is a
handful of lines. Invariant 2 is arguably not a defect here at all, since nothing
races the decision.

Worth mining. The `ctx.invokeTool` delegation pattern is the answer to our open
`ctx.ui.confirm` question and is about 40 lines. Its abort checks are better
placed than ours. If we want the confirm path without raising
`extensionHandlers.toolCallTimeoutMs`, this is the shape to copy — with our
breaker, our audit gate and our fail-closed fallback bolted back on.
