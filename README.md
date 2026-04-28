<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# agent-audit

Forensic auditor for local AI coding agents (Claude Code, Codex CLI, OpenClaw)
**and** project-surface scanner for repos containing skills, plugins, and MCP
manifests. Reads session logs, configs, and instruction files, detects
known-bad patterns using 296 bundled rules in total, including 167
static-file-applicable rules for `scan-project`, plus native ASAMM detectors,
produces a report, and optionally cross-verifies findings using any combination
of installed CLIs, direct API keys, or local LLMs.

`agent-audit` is one of the implementation projects in the broader
[ASAMM](https://github.com/scadastrangelove/asamm/) effort. In ASAMM terms,
this repo is the practical measurement and auditing layer: it turns
agent-safety patterns into something you can run against real repos, local
agent homes, session traces, skill collections, plugin registries, and MCP
manifests.

## Author

Sergey Gordeychik  
scadastrangelove@gmail.com

## Why this project exists

The immediate problem is practical, not purely academic: coding-agent usage
is spreading quickly, and incident reports, prompt-injection cases,
credential leaks, tool-poisoning patterns, and unsafe autonomy examples are
spreading with it. Maintainers need a way to review their own repositories.
Users need a way to triage third-party agent repos before installing skills,
trusting MCP servers, or reusing workflow instructions. `agent-audit` exists
to make that review automatable and repeatable.

The project is deliberately not "just another signature pack". It is a
runner, normalizer, and post-analysis layer around multiple detector
families, with extra native logic for agent-specific control gaps that
generic scanners usually miss.

## Modes at a glance

| Mode | Input | Output | Best for |
| --- | --- | --- | --- |
| `scan` | Local agent home, configs, hooks, session logs | Verified-first forensic report bundle | Incident review, local environment audit, suspicious agent runs |
| `scan-project` | One repo or a corpus of repos with instruction surfaces | Project findings, clustered findings, security profile, collection-scale patterns | Pre-release repo audit, third-party repo triage, corpus research |

## Install

```bash
git clone git@github.com:scadastrangelove/agent-audit.git
cd agent-audit

python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Sanity check:

```bash
agent-audit --help
agent-audit packs
```

## How to use

`agent-audit` has two main operating modes.

### Mode 1: forensic audit of a local agent environment

Use this when you want to inspect a local agent home, session logs, config,
hooks, and traces for known-bad behavior.

Typical cases:

- review a Claude Code or Codex environment after a suspicious run
- inspect whether an agent wrote dangerous config, touched secrets, or
  drifted into unsafe autonomy
- generate a verified incident-style report bundle

Examples:

```bash
# Auto-discover local agent homes and prompt for consent before reading
agent-audit scan

# Write a full report bundle
agent-audit scan --output ./reports/forensic-run -y

# Ask for verifier review as part of the scan
agent-audit scan --output ./reports/forensic-run --verify -y

# Show available detector packs / bundled rules
agent-audit packs
agent-audit packs --all
```

What you get:

- raw findings from logs, configs, and instruction files
- verified-first report bundles for review and sharing
- optional config patch suggestions
- optional verifier re-checks using configured LLM backends

### Mode 2: project / repository surface scan

Use this when you want to audit repos containing `SKILL.md`, `AGENTS.md`,
`CLAUDE.md`, plugin manifests, MCP manifests, tool descriptions, or similar
instruction surfaces.

Typical cases:

- audit your own skill repo before release
- triage third-party agent repos before reuse
- scan a large corpus of repos for research, benchmarking, or regression
  tracking

Examples:

```bash
# Scan one repo
agent-audit scan-project ~/code/my-agent-repo

# Scan a directory of repos and write output artifacts
agent-audit scan-project ~/code/corpus --output ./reports/project-scan -y

# Focus on one imported pack
agent-audit scan-project ~/code/corpus --tool atr
agent-audit scan-project ~/code/corpus --tool cisco-promptguard

# Reduce noise and keep only stronger findings
agent-audit scan-project ~/code/corpus --min-severity high

# See every repeated finding individually instead of collection-scale rollup
agent-audit scan-project ~/code/corpus --no-aggregate
```

What you get:

- `project-findings.json` and `project-findings.md`
- `clustered-findings.json`
- `security-profile.json`
- `files-of-concern.json`
- `report-profiles.json`
- collection-scale aggregation for repeated skill/template patterns

Example output directory from `scan-project --output ./reports/project-scan`:

```text
reports/project-scan/
  project-findings.json
  project-findings.md
  clustered-findings.json
  security-profile.json
  files-of-concern.json
  report-profiles.json
```

## Typical workflow

For maintainers:

1. Run `scan-project` on your repository before publishing.
2. Review `project-findings.md` and `security-profile.json`.
3. Fix or narrow the broadest instruction surfaces first.
4. Re-run with `--min-severity high` for a tighter release gate.

For users evaluating third-party repos:

1. Run `scan-project` on the repo or corpus you plan to reuse.
2. Look first at clustered findings and collection-scale patterns.
3. Treat broad external action, autonomy loops, and trust-boundary expansion
   findings as review priorities.
4. If the repo looks suspicious, follow with `scan` on the actual local
   agent environment after installation/use.

For research / corpora:

1. Scan a directory of repos with `scan-project`.
2. Keep raw, clustered, and aggregate outputs separate.
3. Use `corpus-lab` for regression snapshots and stability checks.

## Signature sources

`agent-audit` currently combines:

- **Native ASAMM detectors** for agent-specific structural gaps such as
  broad external action without approval, autonomous loops with writes, and
  persistent identity rewrite.
- **ATR (Agent Threat Rules)** for prompt injection, agent manipulation,
  excessive autonomy, skill compromise, tool poisoning, context
  exfiltration, and related agent-centric attack patterns.
- **Aguara-derived rules** for external download/install trust-boundary
  expansion, third-party content ingestion, SSRF-cloud, and related remote
  input / remote execution surfaces.
- **Cisco PromptGuard-style rules** for PII harvesting, secret patterns,
  markdown/data-URI exfiltration, and related prompt/output abuse patterns.

The bundled counts are currently:

- `233` ATR rules
- `37` Aguara-derived rules
- `26` Cisco PromptGuard-derived rules
- native ASAMM detectors and project-specific post-processing on top

See [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md) for provenance and
license details.

## Why not just run one upstream pack

Using multiple sources matters, but the bigger value is what `agent-audit`
does *around* them:

- **Surface-aware application.** `scan-project` does not blindly regex every
  file. It classifies instruction surfaces such as `SKILL.md`, `AGENTS.md`,
  plugin manifests, MCP manifests, tool descriptions, and task YAMLs, then
  applies only the relevant rules.
- **Field-aware filtering.** Rules meant for live session events are not
  blindly reused on flat repo text. This removes a large false-positive
  class that appears when session-oriented packs are applied out of context.
- **Native agent-specific logic.** Some important problems are absence-based
  or structural, not just lexical. "Broad action without approval" and
  "persistent identity rewrite" are examples where native detectors add
  signal that raw imported signatures do not provide well.
- **Canonical clustering and deduplication.** Different packs often describe
  different facets of the same dangerous surface. `agent-audit` clusters raw
  rule hits into artifact-backed issue instances instead of treating every
  firing as a separate security fact.
- **Collection-scale aggregation.** When one replicated skill template fires
  hundreds of times, the tool can collapse that into a collection-scale
  pattern instead of flooding the operator with near-identical findings.
- **Severity normalization and reporting.** Imported severities and native
  detector outputs are normalized into one reporting layer, then exposed in
  raw, clustered, and aggregate views.
- **Optional verification.** Findings can be re-checked with external or
  local LLM backends, which is useful when raw pattern matches are noisy or
  context-sensitive.

In short: upstream signatures provide ingredients; `agent-audit` provides
the agent-repo-specific execution model, filtering, clustering, and review
workflow needed to make those ingredients operational.

No active defense — read-only analysis with consent prompts at every step.
Generates ready-to-review config patches, but never applies them.

See [ROADMAP.md](ROADMAP.md) for what's coming.
See [docs/architecture.md](docs/architecture.md) for the technical
architecture — pipeline stages, module layout, how to add detectors/
surfaces/rules. Start here if you're picking up the project.
See [docs/ast-precision-plan.md](docs/ast-precision-plan.md) for the
staged AST / tree-sitter / Rego adoption plan (v0.12 → v1.0).

## Release History

See [CHANGELOG.md](CHANGELOG.md) for current release notes and
[docs/HISTORICAL_CHANGELOG.md](docs/HISTORICAL_CHANGELOG.md) for detailed
research-phase iteration history.
