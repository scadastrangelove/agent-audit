# ATR rule bundle — adapted for agent-audit

Imported from **[Agent-Threat-Rule/agent-threat-rules](https://github.com/Agent-Threat-Rule/agent-threat-rules)**
at commit HEAD of `main`, 2026-04-21.

Upstream license: **MIT, (c) 2026 ATR Contributors**.

## What this is

Verbatim adaptation of 233 ATR detection rules into agent-audit's YAML format.
Regex patterns, test cases, and upstream references are copied character-for-character.
Wrapping, ASAMM mapping, and `audit_surface` fields are agent-audit contributions.

## Naming convention

Every rule has `agent_audit_id` of the form:

```
atr.<category>.<slug-from-title>
```

Prefix `atr.` marks the upstream as ATR. This is distinct from `aegis.`,
`agt.`, and native agent-audit rules (no prefix). Grep-friendly in reports.

The upstream `ATR-2026-NNNNN` id is preserved in `atr_source.original_id`
for round-trip and change-tracking.

## Counts

| Category | Rules |
|---|---:|
| prompt-injection | 88 |
| agent-manipulation | 46 |
| skill-compromise | 36 |
| context-exfiltration | 24 |
| tool-poisoning | 15 |
| privilege-escalation | 9 |
| model-abuse | 7 |
| excessive-autonomy | 5 |
| model-security | 2 |
| data-poisoning | 1 |
| **Total** | **233** |

## ASAMM mapping status

Every rule carries an `asamm` block with `mapping_confidence: category-default`.
This means the primary and secondary ASAMM controls are assigned based on the
ATR category, not per-rule analysis.

Per-rule refinement is a separate pass. When a rule is reviewed and its ASAMM
mapping validated or adjusted, set `mapping_confidence: rule-specific` and add
rationale in `asamm.notes`.

Category defaults applied at import:

| ATR category | ASAMM primary | ASAMM secondary |
|---|---|---|
| prompt-injection | AI-01 | AI-05, AD-01 |
| tool-poisoning | AG-02 | AI-01, AD-03 |
| context-exfiltration | AI-06 | AO-01, AD-01 |
| agent-manipulation | AI-05 | AO-02, AD-01 |
| privilege-escalation | AI-03 | AI-06, AO-02 |
| excessive-autonomy | AD-02 | AI-05, AO-02 |
| skill-compromise | AI-01 | AG-02, AD-04 |
| data-poisoning | AI-04 | AD-01 |
| model-security | AV-02 | AI-05 |
| model-abuse | AI-05 | AV-02, AO-02 |

## audit_surface status

Surfaces are assigned per-category on import. Review per rule to narrow down.
Defaults reflect where the upstream rule is likely to fire:

- `session_*` — runtime forensic (JSONL session logs)
- `instruction_file` — project surface (CLAUDE.md, AGENTS.md, etc.)
- `skill_md`, `mcp_manifest`, `plugin_manifest` — installed/project skill packs
- `memory_store` — persistent agent state

## Next steps for agent-audit integration

1. Write loader (`knowledge/atr_loader.py`) that reads `_index.yaml` + YAML
   files, compiles regex patterns, returns `ATRRule` dataclasses.
2. Write single detector (`detectors/atr_surface.py`) that iterates rules
   against events matching their `audit_surface`, emits `Finding` with full
   ASAMM trace.
3. Refine ASAMM mapping per rule where category default is too coarse.
4. Build reverse converter (`tools/atr_exporter.py`) to emit native
   agent-audit rules back into ATR YAML format for upstream contribution
   (adds `references.asamm` field).
