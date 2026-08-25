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
`mlx-community/gemma-4-e4b-it-qat-OptiQ-4bit` served by mlx, but any endpoint and model work
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
| `endpoint` | `http://127.0.0.1:7777/proxy/gemma-4-e4b/v1` | OpenAI-compatible base URL |
| `model` | `mlx-community/gemma-4-e4b-it-qat-OptiQ-4bit` | as your server names it |
| `timeoutMs` | `10000` | per classification, hard abort |
| `countdownMs` | `3000` | enforce only; you can beat it |
| `externalDirectory` | `true` | also classify external-directory prompts |
| `toasts` | `true` | enforce only; explain each auto-approval |
| `vetoHeadless` | `false` | headless `opencode run` support, opt-in |
| `breakerThreshold` / `breakerCooldownMs` | `3` / `60000` | consecutive failures open the breaker |
| `warmIntervalMs` | `240000` | keeps the model's cached prompt prefix hot; 0 disables |
| `logDir` | `~/.local/share/opencode-local-classifier/logs` | JSONL, one file per day, `0700`/`0600` |

The project file and the plugin options layer are **not** trusted: a repo you clone can
write either, so from those layers only `mode`, `externalDirectory` and `logDir` are
accepted, and the mode may not be raised. Set `trustPluginOptions: true` in the user file if
you genuinely configure this through plugin options.

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
