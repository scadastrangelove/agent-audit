# External scanner rules — adapted for agent-audit

Companion to the ATR bundle (`atr_rules_agent_audit.zip`).

This archive contains **selective imports** from three external AI-agent
security scanners, chosen for **uniqueness relative to ATR**. Overlapping
rules were deliberately excluded — no point duplicating 233 ATR rules
that are already in the ATR bundle.

Import date: 2026-04-21.

## Sources and naming

Three prefixes, grep-friendly:

- `aguara.<category>.<slug>` — from [garagon/aguara](https://github.com/garagon/aguara) (Apache-2.0)
- `cisco-pg.<category>.<slug>` — from the PromptGuard pack bundled inside [cisco-ai-defense/skill-scanner](https://github.com/cisco-ai-defense/skill-scanner) (Apache-2.0)
- Cisco core Python checks — NOT imported as rules; listed in `cisco-core-checks-inventory/INVENTORY.yaml` for manual porting

## What was imported and why

### Aguara selective (37 rules)

Aguara has 189 rules total. ~70-80% of them duplicate ATR categories
(prompt-injection, credential-leak, supply-chain, unicode-attack). Only
the uniquely-valuable categories were imported:

| Category | Rules | Why unique |
|---|---:|---|
| `ssrf-cloud` | 11 | AWS/GCP/Azure metadata endpoints (IMDSv1). ATR does not cover cloud metadata SSRF. |
| `third-party-content` | 10 | Indirect injection from retrieved web content, tool outputs. Narrower than ATR's general prompt-injection. |
| `external-download` | 16 | Supply-chain install scripts (`curl | bash`, typosquat, unpinned `npx -y`). More specific than ATR's supply-chain rules. |

Not imported from Aguara: `prompt-injection`, `credential-leak`,
`exfiltration`, `mcp-attack`, `mcp-config`, `indirect-injection`,
`unicode-attack`, `supply-chain`, `supply-chain-exfil`,
`command-execution` — all heavily overlap with ATR.

### Cisco PromptGuard pack (26 rules)

Imported in full. Covers three categories that are **absent** from both
ATR and your existing rules:

- **`pii_exposure`** (11 rules): US SSN, credit card, IBAN, and other PII
  formats embedded in skill files.
- **`secret_providers`** (9 rules): Extended secret patterns — OpenAI,
  Anthropic, Slack, HuggingFace, npm, PyPI, and more (14 providers total,
  vs. the 8 in Cisco core).
- **`markdown_exfil`** (6 rules): LLM-context exfiltration via markdown
  image tags, link smuggling, HTML injection, data URI payloads.

Note: the PromptGuard pack is bundled **inside** Cisco skill-scanner
under `skill_scanner/data/packs/promptguard/`, and carries its own
attribution in-pack. The upstream PromptGuard project is referenced but
the active distribution is via Cisco.

### Cisco Core Python Checks (inventory only — not ported)

Cisco's `core/python/` directory contains **12 structural analyzers** that
are **not regex rules** — they do things regex cannot:

- `bytecode_checks.py` — `.pyc` without matching `.py`, or AST mismatch (tampering)
- `archive_checks.py` — zip bomb, path traversal in nested archives
- `manifest_checks.py` — skill manifest validation
- `consistency_checks.py` — description-vs-behavior mismatch
- `hidden_file_checks.py` — dotfiles, macOS resource forks, symlinks outside root
- `binary_file_checks.py` — unexpected binaries in skill packages
- `allowed_tools_checks.py`, `asset_checks.py`, `external_tool_checks.py`,
  `file_inventory_checks.py`, `analyzability_checks.py`, `trigger_checks.py`

These are NOT imported because they don't fit the declarative rule model —
they require porting as dedicated Python detectors. Listed in
`cisco-core-checks-inventory/INVENTORY.yaml` for evaluation.

If any of these fill a gap in agent-audit's current detector set, port
them as Python code with attribution comment pointing back to the Cisco
source file.

## Deliberately NOT imported (and why)

| Source | Reason |
|---|---|
| **Cisco core YAML signatures** (45 rules) | Heavy overlap with ATR categories. |
| **Cisco ATR pack** (34 rules) | Subset of ATR 0.4.0 — you have full ATR main (233 rules) via the ATR bundle. |
| **Cisco mcp-scanner YARA** (10 files) | YARA is for binary scanning. Your scope is markdown/JSON/session logs. Categories duplicate ATR. |
| **aguara-mcp** | Go MCP wrapper, not a rule source. |
| **invariantlabs-ai/mcp-scan** | Logic is in Python code (guard.py, pipelines.py), not declarative rules. Main value is their closed Guardrails API. |

## ASAMM mapping status

Every rule has `mapping_confidence: category-default`, same as the ATR
bundle. Refine per rule in a separate pass.

Category defaults applied at import match the ATR bundle mappings where
categories overlap, plus new mappings for PII / markdown exfil:

| Category | ASAMM primary | ASAMM secondary |
|---|---|---|
| pii_exposure | AI-06 | AO-01 |
| secret_providers | AI-06 | AO-01 |
| markdown_exfil | AI-06 | AO-01, AD-01 |
| ssrf-cloud | AI-03 | AI-06, AO-01 |
| third-party-content | AD-01 | AI-01, AG-02 |
| external-download | AG-02 | AI-03, AD-04 |

## Integration notes

Rule schema is almost identical to the ATR bundle, with these differences:

- `external_source` block replaces `atr_source` (different attribution structure)
- `agent_audit_id` prefix varies by tool (`aguara.*`, `cisco-pg.*`)
- Aguara rules carry `targets`, `match_mode`, `examples` (its native format)
- Cisco PromptGuard rules carry `file_types`, `exclude_patterns`

The same loader design described in the ATR bundle's README applies. A
single `knowledge/external_loader.py` can handle both ATR and external
rules by dispatching on the prefix.
