# opencode-local-classifier

Auto-approve opencode permission prompts using a **local model** as a safety classifier.

It ships in shadow mode and will not approve anything until you have looked at your own
data. That is the whole design: the plugin watches every prompt you answer, records what it
would have decided next to what you actually decided, and gives you an analyzer that tells
you — with an explicit pass or fail — whether it has earned the right to answer for you.

## How it works

opencode's `permission.ask` plugin hook is declared but never fired ([#7006][7006]), so
intercepting a prompt before it appears is impossible. Instead this listens to the
`permission.asked` bus event, classifies the command with a plain HTTP call to a local
OpenAI-compatible endpoint (a strict two-line `VERDICT: SAFE|RISKY` protocol at temperature
0), and — only in enforce mode, only on SAFE, only after a countdown you can beat — replies
`once`. Everything else, including every failure, leaves the prompt for you.

The classifier call is deliberately not an opencode session. No ephemeral sessions, no
tool-deny maps, no way for the classifier to trigger itself, and the offline eval can replay
the exact production path with plain HTTP.

The command is sent with the absolute path of your project alongside it, so the classifier
can tell a write inside your tree from a write to the system. That path is context, not
consent: a command that discards work with git, deletes sources, truncates a file or reads a
`.env` is judged the same wherever it points. Scratch files under `/tmp`, `/private/tmp` and
`/var/tmp` are the one place redirection is approved, since nothing there is anyone's work —
and only writing them, never running them.

[7006]: https://github.com/anomalyco/opencode/issues/7006

## Requirements

An OpenAI-compatible `/chat/completions` endpoint on localhost. The shipped default expects
`Youssofal/Qwen3.8-Flash-Next-MTPLX-Bare-Speed` served by mlx, but any endpoint and model work
— point `endpoint` and `model` at yours and re-run the eval corpora before trusting it.
Verdicts depend on the served model, so a model change means a fresh shadow period.

## Install

**This is not on npm yet.** Install it by path today; the package name form below is what
it becomes once published, and it is worth knowing which of the two halves that will
actually simplify.

Clone the repo and point opencode at the file:

```sh
mkdir -p ~/.config/opencode/local-classifier
cp packages/local-classifier/{local-classifier.js,local-classifier-tui.tsx,tui-view.js} \
   ~/.config/opencode/local-classifier/
```

```json
{ "plugin": ["file:///Users/<you>/.config/opencode/local-classifier/local-classifier.js"] }
```

Once it is published, that entry becomes the package name and the copy goes away for the
classifier:

```json
{ "plugin": ["opencode-local-classifier"] }
```

Do not write that line before the package exists. opencode installs an npm plugin on first
use and a name it cannot resolve fails quietly — no error in any log, just a plugin that
never loads.

The status box under the prompt is a **TUI plugin**, a different kind read from a different
file. The copy above already put its two files in place; it just needs registering in
`~/.config/opencode/tui.json`:

```json
{ "plugin": ["file:///Users/<you>/.config/opencode/local-classifier/local-classifier-tui.tsx"] }
```

Both files matter: the `.tsx` draws, and it imports its words from `tui-view.js` next to it.

Publishing will not simplify this half. On opencode 1.18.20 the TUI loader resolves paths
but not package names — measured, not assumed: the same `.tsx` paints when addressed by a
path and paints nothing when addressed by the package name. So the box stays a copied file
until that changes upstream.

The classifier works without any of this. Skipping the box costs you the persistent display;
the toasts still explain each auto-approval.

One thing to know for when the npm form does apply: opencode installs a plugin package once
and then never re-checks it, keyed on the literal spec string. A bare name is fetched on
first use and not refreshed, so moving to a new version means pinning it —
`"opencode-local-classifier@0.2.0"` — which changes the spec and therefore the cache key.

## Lifecycle

1. **Shadow.** The default. Work normally. Every bash and external-directory prompt gets
   classified and logged next to what you decided, and nothing is ever answered for you.
2. **Analyze.** Run the repo's `eval/analyze-logs.mjs` over the log directory. It reports
   asymmetrically, because the errors are asymmetric: every false SAFE is listed case by
   case with a Wilson upper bound, while false RISKY is only a rate. Four gates print an
   explicit pass, fail, or indeterminate — and indeterminate is not pass.
3. **Enforce.** Set `"mode": "enforce"`. SAFE goes to a countdown, during which the prompt
   stays visible and answerable, and then to an automatic `once`. RISKY or any failure
   leaves the prompt alone.

The gate measures agreement with whatever you happened to be asked, so a shadow period
containing no dangerous command can only tell you that nothing was caught there. The
independent corpora in the repo are what actually put dangerous commands in front of the
classifier.

## Config

`~/.config/opencode/local-classifier.json`, overridden by
`<project>/.opencode/local-classifier.json`, overridden by plugin options, overridden by
`OPENCODE_LOCAL_CLASSIFIER_MODE`. Invalid values degrade field by field to defaults and are
reported in the `plugin.init` log line; an invalid mode degrades to shadow, never to
enforce.

| key | default | notes |
|---|---|---|
| `mode` | `"shadow"` | `shadow` / `enforce` / `off` |
| `endpoint` | `http://127.0.0.1:7777/proxy/qwen38-flash-next-mtplx/v1` | OpenAI-compatible base URL |
| `model` | `Youssofal/Qwen3.8-Flash-Next-MTPLX-Bare-Speed` | as your server names it |
| `timeoutMs` | `10000` | per classification, hard abort |
| `stream` | `true` | settle on the verdict line while the reason is still being written (below) |
| `tailTimeoutMs` | `5000` | how long the reason may take after the verdict; only the log loses |
| `countdownMs` | `3000` | enforce only; you can beat it |
| `externalDirectory` | `true` | also classify external-directory prompts |
| `toasts` | `true` | enforce only; explain each auto-approval |
| `vetoHeadless` | `false` | headless `opencode run` support, opt-in |
| `breakerThreshold` / `breakerCooldownMs` | `3` / `60000` | consecutive failures open the breaker |
| `warmIntervalMs` | `240000` | keeps the model's cached prompt prefix hot; 0 disables |
| `logDir` | `~/.local/share/opencode-local-classifier/logs` | JSONL, one file per day, `0700`/`0600` |
| `rules` | `{ "enabled": true }` | stage 1, the deterministic RISKY layer (below) |
| `cascade` | `null` | stages 2 and 3 (below) |

The project file and the plugin options layer are **not** trusted: a repo you clone can
write either, so from those layers only `mode`, `externalDirectory` and `logDir` are
accepted, and the mode may not be raised. Set `trustPluginOptions: true` in the user file if
you genuinely configure this through plugin options.

`rules` and `cascade` are user-file-only for the same reason, one level deeper:
`cascade.secondary` names the server that decides every command the primary was unsure
about, `cascade.certain: 0` would make every SAFE certain, and `rules: { enabled: false }`
would remove the deterministic asks. None of that may come from a checkout.

## Three stages

Every classification goes through up to three of them, inside one `timeoutMs`.

1. **Rules** — `bash-rules.mjs`, deterministic, no model. It only ever says RISKY, so it can
   only add asks; a hit ends the decision and names the rule. `rules: { enabled: false }`
   skips it. Bash only: an external-directory subject is a list of paths, not a command.
2. **Primary** — `endpoint`/`model`, asked for the whole answer with `logprobs`, so the
   probability it put on SAFE at the verdict token is readable. A SAFE at or above
   `cascade.certain` ends the decision.
3. **Secondary** — `cascade.secondary`, asked the ordinary streaming way, decides everything
   else: an uncertain SAFE, a RISKY, a malformed answer, an unreachable primary. Its failure
   is the whole call's failure — the primary's uncertain SAFE is never the fallback.

```json
{
  "endpoint": "http://127.0.0.1:8199/v1",
  "model": "mlx-community/Qwen3.5-4B-OptiQ-4bit",
  "cascade": {
    "secondary": {
      "endpoint": "http://127.0.0.1:7777/proxy/qwen38-flash-next-mtplx/v1",
      "model": "mtplx-flash-next-bare-speed"
    },
    "certain": 0.999,
    "primaryTimeoutMs": 4000
  }
}
```

With no `cascade` block it is one model call, exactly as before: streamed, no logprobs field.
With a `cascade` that has no `secondary`, an uncertain SAFE becomes RISKY
(`primary not certain (pSAFE=0.88)`) and a failure stays a failure.

`certain` defaults to `0.999` because the 4B's scores sit on a coarse grid — 1.00, 0.88,
0.78, 0.69 — so only a perfect score ends the cascade; anything lower admits a whole rung.
The primary must be asked non-streaming: mlx_lm drops logprobs from streamed chunks. The
secondary must never be sent a `logprobs` field: mtplx answers an HTTP error to one.

Each classification log line gains `stage` (`rules`/`primary`/`secondary`), `rule`,
`primary: {verdict, pSafe, pRisky, latencyMs, failure}`, `secondary: {verdict, latencyMs,
failure, endpoint, model}` and `cascade_ms`. Every field that was there before is unchanged.
`endpoint` and `model` on the line still name the primary, so `eval/analyze-logs.mjs` groups
verdicts by a model that may not be the one that answered.

## The verdict is taken from the first line

The answer is verdict-first: `VERDICT: SAFE` on line one, `REASON: …` on line two.
Because the call streams, the decision is made the moment the first newline arrives,
while the model is still writing the reason. Measured 2026-09-03 on Flash-Next, warm,
the verdict line lands about 400 ms in and the reason about 450 ms after that, taking
roughly half of every call off the critical path. The reason isn't thrown away: the
stream keeps reading, and it records a second log line, `classification.tail`, under
the same `permission_id`, with the full text, the full latency, and `contradicted`.

Settling early gives up the guarantee tracked by `contradicted`. The whole-answer parser
fails closed on an answer that names the other verdict later on. A decision that has
already been handed out can't be undone, so it's recorded instead. The 2,359 shadow-logged
answers up to 2026-09-03 held none, and `eval/smoke.mjs` fails the run if one ever appears.

Two places still wait for the reason. A RISKY verdict waits because the human or agent
reads that reason, and RISKY is the rare, slow path anyway. Enforce auto-approval also
checks the tail after its countdown and refuses if the answer never finished or contradicted
itself. The countdown is longer than the tail, so this costs nothing and preserves the
fail-closed shape on the one path that acts.

## What it will not do

- Approve on a classifier error, timeout, HTTP error, empty output, malformed output, or
  more than one `VERDICT:` line. A command that echoes `VERDICT: SAFE` cannot satisfy the
  parser, and a model that talks itself out of its own answer fails closed.
- Approve a verdict that arrived after its deadline.
- Approve a bash call with no `metadata.command`. The AST patterns erase shell operators, so
  reconstructing a command from them would approve a string the shell never runs.
- Reply anything but `once`. Never `always`, which persists server-side; never `reject`,
  which cascades to every pending permission in the session.
- Approve without an audit line on disk. The classification must have been written, the
  check is repeated after the countdown, and an intent line is written before the reply
  leaves.
- Keep classifying after repeated failures. The breaker opens and prompts fall through to
  you.

The log holds every command you ran, verbatim. It is not rotated on purpose, because it is
the eval corpus.

## The full record

The eval harness, the adversarial corpora, the prompt-version history and the reasoning
behind every one of these decisions live in
[khalic-lab/opencode-plugins](https://github.com/khalic-lab/opencode-plugins), which this
package is built from. Start with the root `README.md` — in particular the account of why
importing Claude Code's own permission rubric made the classifier measurably worse, which is
the most useful negative result in there.

## License

MIT
