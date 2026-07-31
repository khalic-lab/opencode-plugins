# Spike — auto-mode for opencode, ideally driven by a local model

**Date:** 2026-07-31 · **Status:** open · **Owner:** rafael.nogueira

Two agents study this independently, one on **claude opus**, one on **fable**. Do not
coordinate. Divergent conclusions are the point — they get compared afterwards.

⚠️ **You share one working tree with the other agent.** Write only your own findings file.
**Do not run `git add`, `git commit`, `git checkout`, `git stash` or anything else that
touches the index** — the other agent is working in the same directory at the same time and
a concurrent index write will corrupt both of your work. Rafael commits at the end.

## Why this exists

opencode has no equivalent of Claude Code's auto mode. Four agents were dispatched on
2026-07-31 and **every one of them stopped on its first action** waiting for a human to
approve `nvm use 22` or `glab issue view NNN`. That is the cost this spike is trying to
remove. Anthropic's own figure — users approve **93%** of permission prompts — is the
argument for automation and simultaneously the argument for why blanket approval is not
the answer.

## What is already established — verify, do not re-derive

Measured against the installed **opencode 1.18.5** (Homebrew,
`/opt/homebrew/Cellar/opencode/1.18.5/`) on 2026-07-31:

- **`--auto` exists**: *"auto-approve permissions that are not explicitly denied
  (dangerous!)"*, default false. Blunt — no judgment, no classifier.
- **Config permissions are static globs.** From opencode's own bundled docs:
  `"permission": { "edit": "deny", "bash": { "git *": "allow", "*": "ask" } }`.
  Values `allow` / `ask` / `deny`; `permission` is either a bare string action or an
  object keyed by tool name.
- **A TUI toggle exists**: `command.permissions.autoaccept.enable` / `.disable`
  ("Auto-accept permissions"). All-or-nothing.
- **Plugin hooks present in the binary**: `chat.message`, `chat.params`,
  `tool.execute.before`, `tool.execute.after`, `permission.ask`.
- ⚠️ **`permission.ask` is defined but NEVER TRIGGERED** —
  https://github.com/anomalyco/opencode/issues/7006, filed 2026-01-05, **still open**.
  `PermissionNext.ask()` publishes a UI bus event without calling plugins first. This is
  the single most important constraint in the spike: the clean interception point does
  not work.
- The `yolo` strings in the binary are **false positives** (Stata syntax grammar,
  SolidJS internals). There is no hidden YOLO mode.

## The existing prior art

`jdtzmn/opencode-delegated-access` v0.4.0 — "Claude auto-mode for opencode".
Read-only clone at `/usr/local/src/khalic-lab/opencode-delegated-access-reference`.

⛔ **STUDY ONLY. Do not install it, do not `bun install` in it, do not run it, do not add
it to any `opencode.json`.** A plugin that can auto-approve bash commands is a very large
trust grant and that decision has not been made. The clone is on disk read-only so you can
read the source; treat it as a document.

What it claims: works around the broken hook by listening to the **`permission.asked`
event**, which fires *after* the TUI has queued the prompt — hence its documented "brief
visual flash" before auto-dismissal. Config: `classifierModel`, `contextMessageCount` (3),
`safeCountdownMs` (5000), `classifierTimeoutMs` (15000), `approvalHistoryEnabled`.
Covers **bash and external directory access only** — edit/write/webfetch unaffected.
Built for opencode **1.4.x**.

## The questions to answer

Answer with evidence — file:line from the reference clone, strings from the binary,
or a measurement. "Probably" is not an answer; "unknown, and here is what would settle
it" is.

1. **Does the 1.4.x event model still hold at 1.18.5?** The plugin assumes
   `permission.asked` fires and can be replied to programmatically. Is that event still
   emitted, with the same shape? Are `permission.asked` / `permission.replied` in the
   1.18.5 binary at all? A 14-minor-version gap is the main reason this could be dead on
   arrival.

2. **Can the classifier be a LOCAL model?** This is the question Rafael actually cares
   about. `~/.config/opencode/opencode.json` already defines an `mlx` provider
   (`@ai-sdk/openai-compatible`, `baseURL: http://127.0.0.1:8081/v1`) serving
   `mlx-community/gemma-4-26B-A4B-it-OptiQ-4bit`, already wired as opencode's
   `small_model`. Does `classifierModel` resolve through opencode's provider registry —
   in which case `"mlx/mlx-community/gemma-4-26B-A4B-it-OptiQ-4bit"` just works — or does
   the plugin hardcode vendor names? Find the resolution code and cite it.

3. **Is `--auto` plus a deny-list good enough?** The cheapest option by far: no plugin, no
   model, no third-party trust. What deny-list would make it acceptable, and what does it
   still get wrong that a classifier would catch? Be concrete — this is the baseline every
   other option has to beat, and it may well win.

4. **What would our own minimal plugin look like?** Given the broken hook, sketch the
   smallest thing that could work against the event system, using the local model. Name
   the failure modes. In particular: **fail-closed is mandatory** — a classifier that
   errors must fall back to asking, never to approving.

5. **Is the local model actually good enough at this?** A 26B-A4B quantised model
   classifying "is this bash command safe" is an empirical question, not a design one.
   Propose how you would measure it — what the eval set looks like, what the failure
   budget is. A false *approve* on `rm -rf` is unrecoverable; a false *ask* is merely
   annoying. Those are not symmetric and the eval must not treat them as such.

## Deliverable

Write `findings/claude.md` or `findings/fable.md` — whichever you were told is yours. That
one file is the only thing you create or modify. Do not commit, do not merge, do not push,
and do not read or touch the other agent's file.

Structure it as: a **recommendation** (one of: use `--auto`+deny-list / adopt the
third-party plugin / build our own / do nothing, and why), then the evidence for each
numbered question above, then what you could **not** determine and what would settle it.

State your confidence per question. An honest "I could not verify this" is worth more here
than a confident guess — the whole point of running two models is to see where they
disagree, and that signal is destroyed if either of you papers over uncertainty.
