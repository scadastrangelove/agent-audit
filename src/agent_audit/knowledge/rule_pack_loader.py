# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Rule pack loader — load YAML rule packs (ATR, Aguara, Cisco PromptGuard).

Rule packs ship as YAML files under knowledge/rule_packs/{atr,external}/.
Each YAML declares regex patterns, ASAMM mapping, audit_surface, severity.

This loader:
- walks the rule_packs/ tree
- parses each YAML into a RulePackRule dataclass
- compiles regex patterns once (cached)
- skips bundle-level metadata files (_index.yaml, INVENTORY.yaml)

See knowledge/rule_packs/atr/README.md and external/README.md for attribution.
"""
from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set

try:
    import yaml  # PyYAML is already transitive via click/rich? if not, add to deps
except ImportError:  # pragma: no cover
    raise ImportError(
        "agent-audit v0.10 requires PyYAML. Install with: pip install pyyaml"
    )

from ..rules import Severity

RULE_PACKS_ROOT = Path(__file__).parent / "rule_packs"
_OVERRIDES_PATH = Path(__file__).parent / "rule_pack_overrides.yaml"

# Files at the root of a pack that are NOT rules (metadata, inventory)
_SKIP_FILENAMES = {"_index.yaml", "INVENTORY.yaml"}


def _load_overrides() -> dict:
    """Load rule-pack overrides — severity demotions and reference rewrites.

    Returns a dict with two top-level keys:
        rules:                  per-rule severity / reference overrides
        references_rewrite:     global ref-text rewrites by exact match
    """
    if not _OVERRIDES_PATH.exists():
        return {"rules": {}, "references_rewrite": {}}
    try:
        doc = yaml.safe_load(_OVERRIDES_PATH.read_text()) or {}
        return {
            "rules": doc.get("rules") or {},
            "references_rewrite": doc.get("references_rewrite") or {},
        }
    except Exception:
        return {"rules": {}, "references_rewrite": {}}


_OVERRIDES = _load_overrides()
_OVERRIDES_RULES = _OVERRIDES["rules"]
_OVERRIDES_REWRITES = _OVERRIDES["references_rewrite"]


def _apply_reference_rewrites(references: dict) -> dict:
    """Apply global text-replacement overrides to references.

    Used to fix upstream taxonomy drift (e.g. MITRE ATLAS renamed
    'ML Supply Chain Compromise' to 'AI Supply Chain Compromise')
    without editing upstream rule YAMLs.

    The override file's `references_rewrite` block has shape:
        references_rewrite:
          mitre_atlas:
            "AML.T0010 - ML Supply Chain Compromise":
              "AML.T0010 - AI Supply Chain Compromise"

    Lookup is exact-match on the cited string. Misses pass through
    unchanged.
    """
    if not _OVERRIDES_REWRITES:
        return references
    out = dict(references)
    for ref_field, rewrites in _OVERRIDES_REWRITES.items():
        if not isinstance(rewrites, dict):
            continue
        existing = out.get(ref_field)
        if not existing:
            continue
        if isinstance(existing, list):
            out[ref_field] = [rewrites.get(str(v), v) for v in existing]
    return out


@dataclass
class RulePackRule:
    """A single rule from an external pack, normalized to agent-audit internals."""

    agent_audit_id: str
    title: str
    description: str
    category: str
    severity: Severity

    # Where this rule applies (declared in YAML)
    audit_surface: Set[str]

    # Compiled regex patterns (one rule -> one or more)
    patterns: List[re.Pattern]
    # Compiled exclude patterns — a match here suppresses the finding
    exclude_patterns: List[re.Pattern]

    # Attribution
    source_tool: str           # "atr" / "aguara" / "cisco-promptguard"
    source_original_id: str    # "ATR-2026-00001" / "SSRF_001" / "PG_PII_SSN"
    source_license: str
    source_upstream: str

    # ASAMM trace
    asamm_primary: str
    asamm_secondary: List[str]

    # Upstream references (OWASP / MITRE / CVE)
    references: dict = field(default_factory=dict)

    # Optional hints for callers
    file_types: List[str] = field(default_factory=list)
    remediation: str = ""

    # M3 — NOVA evaluator metadata. Populated only for NOVA rules; empty
    # for everything else. The evaluator uses these to run semantics/llm
    # gates after the regex pre-match. See nova_evaluator.py.
    upstream_semantics_patterns: List[dict] = field(default_factory=list)
    upstream_llm_checks: List[dict] = field(default_factory=list)
    # The pre-flooring severity from the .nov file, before A2/C1 demoted
    # everything to LOW. Used to decide how high the evaluator can lift
    # a finding when both gates pass. None = unknown (older imports).
    upstream_severity: Optional[Severity] = None


def _severity_from_string(s: str) -> Severity:
    m = (s or "medium").strip().lower()
    try:
        return Severity(m)
    except ValueError:
        return Severity.MEDIUM


# Fields that make sense to match against static file content.
# Other fields (user_input, tool_args, tool_name, tool_response, agent_output)
# are session-event-specific — applying their regex to plain file text
# produces systematic false positives on documentation.
_STATIC_FILE_FIELDS = {"content", "description", "tool_description", None, ""}


def _compile_patterns(patterns_field, *, static_only: bool = False) -> List[re.Pattern]:
    """Normalize the various pattern shapes used across ATR/Aguara/Cisco.

    - ATR: detection.conditions = [{field, operator, value, description}, ...]
    - Aguara: patterns = [{type: regex, value: "..."}, ...] or [{type: contains, value}]
    - Cisco PG: patterns = ["regex1", "regex2", ...]

    When static_only=True (default for the project scanner), skip ATR
    conditions that target session-event-specific fields like `tool_name`
    or `user_input`. Those rules are designed for live trace data, not
    flat file text; applying them to documentation produces FPs.
    """
    compiled: List[re.Pattern] = []
    if not patterns_field:
        return compiled
    for item in patterns_field:
        if isinstance(item, str):
            # Cisco PG style: raw regex strings
            pat = item
        elif isinstance(item, dict):
            # ATR condition: {field, operator: regex, value}
            if item.get("operator") in {"regex", None} and "value" in item:
                if static_only and item.get("field") not in _STATIC_FILE_FIELDS:
                    continue
                pat = item["value"]
            # Aguara: {type: regex, value} or {type: contains, value}
            elif item.get("type") == "regex":
                pat = item.get("value", "")
            elif item.get("type") == "contains":
                # Treat as literal, escape metacharacters
                pat = re.escape(item.get("value", ""))
            else:
                continue
        else:
            continue
        if not pat:
            continue
        try:
            with warnings.catch_warnings():
                # POSIX character classes like [[:alnum:]] in Gitleaks rules
                # raise a FutureWarning under Python 3.12+ but compile fine.
                # Suppress at the compile step — the regex still works.
                warnings.simplefilter("ignore", FutureWarning)
                compiled.append(re.compile(pat))
        except re.error:
            # Skip malformed regex — log at caller level if needed
            continue
    return compiled


def _compile_exclude_patterns(excludes) -> List[re.Pattern]:
    compiled: List[re.Pattern] = []
    if not excludes:
        return compiled
    for item in excludes:
        if isinstance(item, str):
            pat = item
        elif isinstance(item, dict):
            if item.get("type") == "regex":
                pat = item.get("value", "")
            elif item.get("type") == "contains":
                pat = re.escape(item.get("value", ""))
            else:
                continue
        else:
            continue
        try:
            compiled.append(re.compile(pat))
        except re.error:
            continue
    return compiled


def _parse_one(yaml_path: Path, *, static_only: bool = True) -> Optional[RulePackRule]:
    """Parse a single pack YAML into a RulePackRule, or None if not a rule."""
    try:
        doc = yaml.safe_load(yaml_path.read_text())
    except Exception:
        return None
    if not isinstance(doc, dict):
        return None
    # Must have agent_audit_id to be a rule
    aaid = doc.get("agent_audit_id")
    if not aaid:
        return None

    # Source attribution — ATR uses atr_source, external packs use external_source
    src = doc.get("atr_source") or doc.get("external_source") or {}
    source_tool = src.get("tool", "atr" if "atr_source" in doc else "unknown")
    source_original_id = src.get("original_id", "")
    source_license = src.get("license", "")
    source_upstream = src.get("upstream", "")

    asamm = doc.get("asamm", {}) or {}
    audit_surface = set(doc.get("audit_surface") or [])

    # Patterns live in one of three shapes depending on origin
    patterns_field = None
    if "detection" in doc and isinstance(doc["detection"], dict):
        patterns_field = doc["detection"].get("conditions")
    if not patterns_field:
        patterns_field = doc.get("patterns")

    compiled = _compile_patterns(patterns_field, static_only=static_only)
    if not compiled:
        # A rule with zero compiled patterns is not useful for this detector
        return None

    excludes = doc.get("exclude_patterns")
    compiled_excludes = _compile_exclude_patterns(excludes)

    # Apply severity override from rule_pack_overrides.yaml (Fix 1 from
    # grand-run analysis — demote noisy rules without editing upstream).
    raw_severity = doc.get("severity_default") or doc.get("severity", "medium")
    override = _OVERRIDES_RULES.get(aaid, {})
    if override and "severity" in override:
        raw_severity = override["severity"]

    # Map Aguara's `targets:` field (file extension globs) into file_types.
    # When the rule explicitly targets specific extensions, we'll filter
    # at match time so that e.g. a rule targeting *.pth doesn't fire on
    # Markdown documentation that mentions the same string.
    targets_field = doc.get("targets") or []
    file_types = list(doc.get("file_types") or targets_field)

    # Build references with two layers of normalization:
    #   1. text rewrites (e.g. ATLAS taxonomy name drift)
    #   2. derived OWASP MCP Top 10 mapping (Roadmap B1)
    references = _apply_reference_rewrites(dict(doc.get("references", {}) or {}))
    if "owasp_mcp" not in references:
        try:
            from .owasp_mcp_mapping import owasp_mcp_for_pack_category, owasp_mcp_label
            mcp_ids = owasp_mcp_for_pack_category(source_tool, str(doc.get("category", "")))
            if mcp_ids:
                # Format as "MCPNN - Title" to match the cited-name convention
                # used for owasp_llm / owasp_agentic / mitre_atlas elsewhere.
                references["owasp_mcp"] = [
                    owasp_mcp_label(mid) or mid for mid in mcp_ids
                ]
        except Exception:
            # Mapping module is optional infrastructure — never fail rule load
            # over it. The validator catches missing mappings separately.
            pass

    # Same enrichment for OWASP Agentic Applications Top 10 (Roadmap B2).
    # Independent from owasp_mcp: ASI taxonomy spans wider risks (inter-agent
    # comms, memory poisoning, rogue agents) that MCP Top 10 does not cover.
    if "owasp_agentic" not in references:
        try:
            from .owasp_agentic_mapping import owasp_agentic_for_pack_category, owasp_agentic_label
            asi_ids = owasp_agentic_for_pack_category(source_tool, str(doc.get("category", "")))
            if asi_ids:
                references["owasp_agentic"] = [
                    owasp_agentic_label(aid) or aid for aid in asi_ids
                ]
        except Exception:
            pass

    # B4 — AVID (AI Vulnerability Database) cross-link. SEP subcategories
    # only; lifecycle stages and per-record AVID-YYYY-V/R IDs are out of
    # scope. Independent from MCP/ASI: AVID groups by failure mechanism
    # (Software Vulnerability vs Information Leak vs Model Bypass)
    # whereas OWASP MCP/ASI group by agent-specific risk class.
    if "avid" not in references:
        try:
            from .avid_mapping import avid_for_pack_category, avid_label
            sep_ids = avid_for_pack_category(source_tool, str(doc.get("category", "")))
            if sep_ids:
                references["avid"] = [
                    avid_label(sid) or sid for sid in sep_ids
                ]
        except Exception:
            pass

    # M3 — pull NOVA evaluator metadata if present. Non-NOVA rules don't
    # set these fields, so the lists default to empty. Reading them
    # unconditionally is cheap and uniform across rule packs.
    upstream_semantics_patterns = list(doc.get("upstream_semantics_patterns") or [])
    upstream_llm_checks = list(doc.get("upstream_llm_checks") or [])
    upstream_sev_raw = doc.get("upstream_severity")
    upstream_severity_obj: Optional[Severity] = None
    if upstream_sev_raw:
        try:
            upstream_severity_obj = Severity(str(upstream_sev_raw).strip().lower())
        except ValueError:
            upstream_severity_obj = None

    return RulePackRule(
        agent_audit_id=aaid,
        title=str(doc.get("title", aaid)),
        description=str(doc.get("description", "")).strip(),
        category=str(doc.get("category", "")),
        severity=_severity_from_string(raw_severity),
        audit_surface=audit_surface,
        patterns=compiled,
        exclude_patterns=compiled_excludes,
        source_tool=source_tool,
        source_original_id=source_original_id,
        source_license=source_license,
        source_upstream=source_upstream,
        asamm_primary=asamm.get("primary", ""),
        asamm_secondary=list(asamm.get("secondary", []) or []),
        references=references,
        file_types=file_types,
        remediation=str(doc.get("remediation", "")),
        upstream_semantics_patterns=upstream_semantics_patterns,
        upstream_llm_checks=upstream_llm_checks,
        upstream_severity=upstream_severity_obj,
    )


_CACHE: dict = {}  # keyed by static_only bool


def load_all_rules(
    root: Optional[Path] = None,
    force_reload: bool = False,
    *,
    static_only: bool = True,
) -> List[RulePackRule]:
    """Load every rule pack under rule_packs/. Cached per process per mode.

    static_only=True (default) filters out ATR conditions that target
    session-event fields like tool_name/user_input — those were designed
    for live trace data and systematically FP on flat file text.

    static_only=False is reserved for a future session-aware scanner.
    """
    global _CACHE
    key = bool(static_only)
    if key in _CACHE and not force_reload:
        return _CACHE[key]
    root = root or RULE_PACKS_ROOT
    rules: List[RulePackRule] = []
    if not root.exists():
        _CACHE[key] = rules
        return rules
    for yaml_path in root.rglob("*.yaml"):
        if yaml_path.name in _SKIP_FILENAMES:
            continue
        rule = _parse_one(yaml_path, static_only=static_only)
        if rule is not None:
            rules.append(rule)
    _CACHE[key] = rules
    return rules


def rules_for_surface(surface: str, rules: Optional[List[RulePackRule]] = None) -> List[RulePackRule]:
    """Subset of rules that declare this audit_surface."""
    all_rules = rules if rules is not None else load_all_rules()
    return [r for r in all_rules if surface in r.audit_surface]


def pack_summary(*, static_only: bool = True) -> dict:
    """Overview of what's loaded. Useful for `agent-audit packs` command."""
    rules = load_all_rules(static_only=static_only)
    by_tool: dict = {}
    by_category: dict = {}
    by_severity: dict = {}
    for r in rules:
        by_tool[r.source_tool] = by_tool.get(r.source_tool, 0) + 1
        by_category[r.category] = by_category.get(r.category, 0) + 1
        by_severity[r.severity.value] = by_severity.get(r.severity.value, 0) + 1
    return {
        "total": len(rules),
        "by_tool": dict(sorted(by_tool.items(), key=lambda kv: -kv[1])),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: -kv[1])),
        "by_severity": dict(sorted(by_severity.items(), key=lambda kv: -kv[1])),
    }
