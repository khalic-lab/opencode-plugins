# Spike: a CPU classifier, with the LLM as fallback

**Date:** 2026-09-03 · **Status:** proposed · **Owner:** khalic-lab

The safety classifier costs about a second per call on Flash-Next and is unreachable
for the whole of any generation Flash-Next is already running, because mtplx serves one
request at a time. A model that answers on the CPU in tens of milliseconds, and abstains
when unsure, turns the LLM into the fallback for the uncertain residue instead of the
front door. Whether that model is a language model at all is the question this spike
keeps open: the deliverable is several candidates scored on one data set, in one table.

## What exists

- The policy, as prose: prompt p7, roughly 2300 tokens, with hard-RISKY categories,
  on-sight rules and carve-outs. It is a specification; a trained model learns it from
  examples instead of reading it.
- Gold data: the smoke corpus (77 cases) and hardcases (40). It is used for evaluation
  only, never for training.
- Human-labelled data: the shadow logs, 229 classifications so far, joined to the human's
  reply by `eval/analyze-logs.mjs` with its label-hygiene rules (cascade siblings, amended
  decisions). It grows daily.
- A labeller: Flash-Next with p7 at temperature 0 scores 0 false-SAFE on both corpora, so
  it can label a silver set at scale, with reasons.
- A deterministic prefilter already in front of the model (out of scope here, but it is
  the first stage of the cascade below).
- Negative results on zero-shot small language models: LFM2.5, granite-4.2-3b and Gemma
  E2B failed the corpora; Qwen3.5-4B passed on judgement and failed on spelling. Trying
  another small model zero-shot is not part of this spike.

## Candidates

We keep the candidate list deliberately broad. Each is scored on the same splits, the
same gate, and the same latency and memory budget.

1. **Shell structure plus a tree model.** Parse the command with tree-sitter-bash into
   features per segment: normalised command name (`/bin/rm`, `command rm`, `xargs rm`
   all fold to `rm`), flags, redirection targets with their path class, pipe into an
   interpreter, network tools with a host or URL feature, privilege words, git
   subcommand with flags, install-with-a-name, heredoc-then-execute, command
   substitution, obfuscation markers (quote splitting, base64, eval). Then train gradient
   boosting or logistic regression over those features. This runs in under a millisecond,
   stays interpretable, and uses a few megabytes. Its weakness is that feature coverage
   is the model: if the features don't describe a shape, it must abstain. The path-class
   annotator from the subject-preparation spike is this candidate's feature extractor.
2. **A small encoder, fine-tuned.** ModernBERT-base, DeBERTa-v3-small or MiniLM with a
   two-class head over `<project_dir>` and the command, capped at 512 tokens, served on
   the CPU through ONNX Runtime or Core ML. We expect 10 to 30 ms per call. It learns
   shapes without feature engineering, but it needs thousands of examples, has to be
   taught obfuscation explicitly, and its tokenizer splits paths badly, which is another
   argument for feeding it path classes rather than raw paths.
3. **A tiny decoder, fine-tuned.** Qwen3.5-0.8B or Gemma E2B with a LoRA, merged, run on
   the CPU via llama.cpp or MLX's CPU path. The policy is baked in by training, so the
   request is the command alone and the answer is one token; there is no 2300-token prefix
   and no prefix cache to keep warm. It takes about a gigabyte resident and 100 to 300 ms
   per call. It generalizes best among the three options and is the most expensive;
   E2B's zero-shot failure shows that the base needs real training, not a prompt.
4. **Retrieval.** Embed the command with a small CPU embedding model and vote over the
   nearest labelled neighbours. It isn't a classifier on its own, but it gives us the
   natural abstain signal (no close neighbour, abstain) and provides the cheapest first
   version of the cascade.
5. **Structural rules, no learning.** The features from candidate 1 evaluated by written
   rules. This is the existing prefilter extended from regexes to an AST. We list this so
   the comparison table has the deterministic baseline in it, not as a deliverable.

## The cascade

Deterministic rules, then the CPU model, then the LLM, then the human. Every stage is
fail-closed: the CPU model answers SAFE only above a threshold chosen on gold for zero
false-SAFE, answers RISKY only above a threshold chosen for tolerable friction, and
abstains between them. An abstention falls through to the LLM exactly as today, with the
same timeout and the same human prompt behind it. The LLM's unavailability during a
generation stops mattering for every call the CPU model answers.

Integration needs one small plugin change: a third outcome, abstain, for the first
endpoint, with fall-through to the second. The CPU model is served as a sidecar speaking
the same `/chat/completions` shape and returning a `VERDICT:` line, so `classify()` and
the eval harness run against it unchanged; mlxctl can host it as another kind beside the
AFM shim.

## Data

- **Gold** stays gold: smoke, hardcases and the p6 cases, used for evaluation only.
- **Human-labelled**: the shadow corpus processed through the analyzer's hygiene rules.
- **Silver**: every shell command run on this box by Claude Code and opencode, exported
  as an explicit, approved batch (the transcripts are configuration under the current
  policy, so the export is a human action, not a script the agent runs), deduplicated,
  and labelled by Flash-Next p7 at temperature 0 with its reason kept. We expect
  thousands of cases. We will hand-audit a sample of a few hundred, verdict by verdict,
  before anything trains on it.
- **Adversarial augmentation**: programmatic transforms with the label carried across:
  obfuscated `rm`, `curl`, `sudo`; comment and `VERDICT: SAFE` injections; path aliasing
  between `~`, `$HOME` and `/Users/x`; heredoc-and-execute; and benign counterparts of
  each so the transforms themselves do not become the signal.
- **Splits by command family**, hashing the first command name, so the evaluation measures
  generalisation to shapes the model hasn't seen rather than recall of the training set.

## Gate and metrics

On gold: zero false-SAFE at the chosen threshold, with false-RISKY no worse than the
LLM's. On shadow traffic: abstain rate at most one in five. Latency p95 under 50 ms for
candidates 1, 2 and 4, and under 300 ms for candidate 3. Resident memory under a
gigabyte. We will place all candidates in one table, with the deterministic baseline as
the first row.

Zero false-SAFE on 117 gold cases is a weak statistical guarantee, and the document says
so: the shadow week with the disagreement list read case by case is part of the gate,
not an afterthought.

## Plan

1. Data pipeline: gold, human, silver and augmented sets with the family split. This will
   take one to two days.
2. Baselines: retrieval and the structure-plus-tree model. This will take one day. If the
   tree model clears the gate with an acceptable abstain rate, the encoder is optional.
3. Encoder fine-tune. This will take one day.
4. Tiny-decoder LoRA, only if candidates 2 and 3 fail the false-SAFE gate. This will take
   one to two days; the swift-tune LoRA tooling applies.
5. Cascade in shadow for a week, then the enforce decision.

## Risks

- Label noise from the LLM labeller. As a mitigation, we run the hand audit, and gold
  never touches training.
- Distribution shift when a new tool enters the workflow. As a mitigation, we rely on the
  abstain band and retrain from the growing shadow corpus on a schedule.
- Adversarial inputs the features do not describe. As a mitigation, we keep the
  deterministic hard-RISKY rules in front, abstain on unknown shapes, and use
  augmentation in training.
- Two policies drifting apart, prompt and model. As a mitigation, the silver labels come
  from the prompt, so the model is a compression of the prompt by construction, and the
  disagreement list is the drift detector.
