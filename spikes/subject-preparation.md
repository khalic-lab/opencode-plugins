# Spike: prepare the subject before the model sees it

**Date:** 2026-09-03 · **Status:** proposed · **Owner:** khalic-lab

The classifier passes the model a raw command string of up to 4000 characters
along with a `<project_dir>` element. It then spends about 400 tokens of system
prompt teaching the model how to parse paths: what counts as inside the project,
which three locations are the agent's own working areas, and why
`/Users/x/.claude/projects/.../memory` isn't "a home path". The plugin can compute
every one of those judgements before building the request. This spike prepares
the subject in code so the model gets less text and makes fewer decisions.

## What is measured today (Flash-Next, single tenant, 2026-09-02)

- A warm classification takes about 1.0 s at p50 and 1.8 to 2.0 s at p95. A call
  with a cached prefix bottoms out at roughly 430 ms.
- mtplx's session bank serves the system prompt on every warm call, so only the
  user message gets prefilled. In practice, that message is the `<project_dir>`
  element plus the command, totaling 30 to 400 tokens.
- The slowest cases in the corpus are path-heavy: directory grants, heredocs, and
  scratchpad paths where a 36-character session id appears two or three times.
- In shadow logs (229 classifications), bash subjects are 111 characters at the
  median, 527 at p90, and 1656 at most. Directory subjects are 35 at the median
  and 143 at most.
- The output-format A/B (`/tmp/cb-ab.results.json`) breaks down how much of that
  second comes from decoding the REASON line versus prefilling the subject. The
  split probe in the same file gives ttft against decode for each case. Check
  those numbers before estimating the latency gains here.

Here are the realistic limits: shrinking the subject saves prefill tokens, and
prefill runs at about 800 tokens per second. Folding 150 tokens saves under
200 ms, and only on the longest cases. The latency gains show up at p95 rather
than p50. The other half of this spike, path annotations, targets misjudgements
instead of milliseconds. Those classification errors were what led to prompt
versions p6 and p7 in the first place.

## Hypotheses

1. Rewriting path-heavy subjects into the prompt's own notation will preserve
   every verdict across the corpora while measurably dropping p95 on those cases.
2. Passing deterministic path classes to the model (project, scratchpad, memory,
   tmp, home, system, outside) will eliminate the false-RISKY verdicts that p7
   addressed, letting us trim the prompt's working-area paragraphs in a later
   update.
3. Every fold can fail safely: whenever the preparer is unsure, it can fall back
   to the raw subject so the request matches current behavior.

## Design

A single pure function in the plugin, `prepareSubject(kind, subject, projectDir)`,
returns `{ text, annotations, folded, abstained }`. It runs between `buildSubject`
and `buildUserPrompt`. Each classification line logs the result so the analyzer
can trace any disagreement back to the preparer. The stages run in this order:

**Parse.** The stage splits the command into segments and classifies each token:
command name, flag, path, redirection target, heredoc body, quoted literal, and
whether a literal is a code payload (an argument to `bash -c`, `sh -c`, `python -c`,
`node -e`, `eval`, `source`, or piped into an interpreter). tree-sitter-bash is
the candidate parser, with a dedicated hand parser for these shapes as the
fallback. If the parser encounters anything unexpected, the whole function
abstains.

**Fold, only in data positions.** Code payloads stay untouched. For data positions:

- The home directory prefix becomes `~`, so `/Users/x/.claude/projects/p/memory/MEMORY.md`
  matches the prompt's example format. The session-id segment in a scratchpad path
  becomes `<session>`, matching the prompt's notation so the working-area rule
  hits familiar text instead of a UUID the model must evaluate.
- Heredoc bodies written to a temp or working-area file without being executed in
  the same command are capped at a set number of lines with an explicit
  `[... N more lines]` marker. Any body that is executed, sourced, or piped stays
  intact.
- Base64 and hex blobs retain their initial characters alongside an `[N chars]`
  marker. The on-sight rule keys on the presence of `base64 -d`, not the payload.
- Long quoted literals representing plain data (such as a commit message or
  printf body) are truncated with a marker. Runs of whitespace collapse.

**Annotate.** Each path gets a class computed from `projectDir`, the known working
areas, and the temp roots: `[project]`, `[scratchpad]`, `[memory]`, `[plans]`,
`[tmp]`, `[home]`, `[system]`, `[outside]`. These are output as a compact
`<paths>` block under the command, with one line per distinct path. The classes
supply facts rather than verdicts: a `[project]` `.env` file remains a credential
read as defined in the prompt.

**Keep-verbatim list.** The preparer rejects any fold that removes or modifies a
token targeted by a hard-RISKY rule: `rm`, `sudo`, `curl`, `wget`, `nc`, `base64`,
`eval`, `>`, `.env`, `.ssh`, `id_rsa`, `credentials`, and the remaining tokens
specified in the current prompts. This list lives in a test fixture rather than a
comment.

**Prompt.** Version p8 adds one paragraph to p7 describing the notation: `~`,
`<session>`, the path classes, and the `[... N more lines]` opaque content marker.
Nothing else in the prompt changes for this spike. Trimming the working-area
paragraphs is a separate follow-up that depends on the parity results.

**Sanitisation.** If a command already contains literal `[project]` or `<paths>`
text, the plugin escapes it just as `sanitizeSubject` escapes closing tags today.
This prevents forging the annotation channel from inside the subject.

## Measurement

- Offline, before altering any prompts: compare token counts of raw versus
  prepared subjects across smoke, hardcases, and the shadow corpus using mtplx's
  count_tokens endpoint. If p95 savings fall below roughly 100 tokens, running a
  parser in the approval path is not worthwhile, and we will proceed with only the
  annotation changes.
- Verdict parity on the corpora using the output-format A/B harness (a copy of
  the tree with the preparer enabled): false-SAFE must remain at zero,
  false-RISKY must not increase, and latencies must be compared pairwise for each
  case rather than by p50 alone.
- One week in shadow mode: classify both the raw and prepared requests for every
  invocation. The analyzer's disagreement list will serve as the review queue.
  We will not enforce the prepared path until we have reviewed that list case by
  case.

## Exit criteria

We require parity across every corpus, a drop in p95 on path-heavy cases that
matches split-probe predictions, and a shadow-week review where every prepared
verdict is defensible. If we miss corpus parity, we will drop the folding stage
and evaluate the annotation stage solely on its false-RISKY count.

## Risks

- Parser divergence between zsh execution and bash parsing. The abstain rule and
  a test corpus derived from shadow logs mitigate this risk.
- A fold hiding a code payload. We mitigate this by restricting folds to data
  positions, maintaining the keep-verbatim list, and enforcing the
  executed-in-the-same-command rule for heredocs.
- Annotations turning into a secondary policy. Path classes must remain facts
  for the prompt to evaluate. If a class starts dictating a verdict, that logic
  belongs in the deterministic prefilter rather than this function.

## Effort

Building the function and its test fixtures will take one to two days, followed
by half a day for the offline parity and latency benchmarks, and then an
unattended one-week shadow run.
