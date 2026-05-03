# Injection benchmark corpora — how-to

This document covers how to set up the AgentDyn (D2) and WASP (D3)
prompt-injection corpora for use with `agent-audit injection-benchmark`.
Neither corpus is bundled with `agent-audit` — see the licensing notes
below for why.

## Quick start

```bash
# Clone whichever corpora you want to measure against
git clone --depth 1 https://github.com/SaFo-Lab/AgentDyn.git ~/corpora/AgentDyn
git clone --depth 1 https://github.com/facebookresearch/wasp.git ~/corpora/wasp

# Run rule packs against both corpora and write a report
agent-audit injection-benchmark \
  --agentdyn ~/corpora/AgentDyn \
  --wasp ~/corpora/wasp \
  -o /tmp/recall.json
```

The output prints per-suite recall plus the top 10 rules by contribution
to detection. The JSON file (`-o`) carries the same data plus a sample
of undetected cases for follow-up analysis.

## What the benchmark measures

Recall on adversarial cases — fraction of known-injection prompts where
at least one rule pack pattern fires. **The benchmark does not measure
precision.** Precision needs a paired benign corpus, which lives
separately (we use a calibration corpus of benign skill SKILL.md files).

A high recall number with a known FP rate on benign content tells you
which rules carry their weight versus which need the M3 NOVA evaluator
gating to lift severity safely. That's the actionable signal.

## License notes

### AgentDyn (D2)

- **License**: MIT (the `SaFo-Lab/AgentDyn` repo).
- **Bundling**: technically allowed, but the upstream tree is heavy
  (~50K files). We don't redistribute it; clone locally instead.
- **Citation**: AgentDyn paper (arXiv:2602.03117) — cite if benchmark
  results appear in a publication.

### WASP (D3)

- **License**: **CC-BY-NC 4.0** for the data portion. Code is mixed
  (visualwebarena pieces are MIT; the rest is non-commercial).
- **Bundling**: explicitly NOT allowed under non-commercial. We do
  not redistribute. Clone locally.
- **Use**: research and academic measurement is fine; commercial
  evaluation pipelines need separate licensing arrangements with the
  upstream authors.
- **Citation**: WASP paper (arXiv:2504.18575).

## How the adapters work

### AgentDyn adapter

AgentDyn is an AgentDojo-extended Python framework. Injection cases live
as Python classes under
`src/agentdojo/default_suites/<version>/<suite>/injection_tasks.py`,
each with a `GOAL = "..."` class-level attribute carrying the injection
text. The adapter walks these files via `ast.parse`, finds classes with
`Injection` in their name, and extracts the GOAL string. It substitutes
class-level constants like `_RECIPIENT = "x@y.com"` into the GOAL so
rule packs see the literal text rather than placeholders.

What the adapter does NOT do:
- Run the upstream agent harness. AgentDyn requires playwright + LLM
  API keys + 60+ runtime dependencies — out of scope for static
  rule-pack measurement.
- Resolve dynamic Python expressions inside f-strings. References like
  `{self.environment.email}` stay as `{self.environment.email}` in the
  text (literal-only substitution). Rule packs match around the
  placeholders rather than through them.

### WASP adapter

WASP cases live in
`webarena_prompt_injections/configs/experiment_config.raw.json`. Each
entry has an `instruction` field carrying the injection text plus a
`parameters` dict for `{placeholder}` substitution. The adapter reads
the JSON, substitutes parameters, and tags each case with
`environment` and `exfil` metadata. The full agent execution loop
(WebArena + selenium) is bypassed — same as for AgentDyn.

## Empirical baseline numbers

As of v0.17.0 with all five rule packs loaded (atr, aguara,
cisco-promptguard, gitleaks, nova), measured against current upstream
clones of both corpora:

- **AgentDyn**: 82 cases harvested. Recall **93.9%** (77/82 detected).
  Top contributing rule: `nova.prompt-injection.policy-puppetry-universal-bypass`
  on 53 cases.
- **WASP**: 21 cases harvested. Recall **100.0%** (21/21 detected).
  Top contributing rule: `nova.prompt-injection.job-recruitment-variation-rule`
  on 14 cases.

These numbers should be reproduced periodically — both corpora ship
updates. A regression below 80% recall on AgentDyn warrants
investigation; that's the threshold for "still useful as detection
layer". WASP's smaller corpus is more sensitive — single-case shifts
move recall by ~5%.

## Failure modes

The adapters return `[]` (empty list) rather than raising in three
common situations:

1. **Repo path doesn't exist**: someone passes a typo'd `--agentdyn`
   path. The CLI prints "0 cases" and moves on.
2. **Upstream layout changes**: AgentDyn moves files out of
   `default_suites/`. The adapter falls back to a wider
   `**/injection_tasks.py` walk.
3. **Malformed config**: WASP's experiment_config.raw.json contains
   broken JSON. The adapter logs nothing and returns `[]` so the rest
   of a multi-corpus run continues.

For #2 and #3, a `0` case count from the adapter is a signal to
re-clone or report upstream — not a silent failure. The CLI surfaces
the count explicitly.
