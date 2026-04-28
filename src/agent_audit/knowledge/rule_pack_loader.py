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
    """Load per-rule severity overrides. Returns {} if file missing."""
    if not _OVERRIDES_PATH.exists():
        return {}
    try:
        doc = yaml.safe_load(_OVERRIDES_PATH.read_text()) or {}
        return (doc.get("rules") or {})
    except Exception:
        return {}


_OVERRIDES = _load_overrides()


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
    override = _OVERRIDES.get(aaid, {})
    if override and "severity" in override:
        raw_severity = override["severity"]

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
        references=doc.get("references", {}) or {},
        file_types=list(doc.get("file_types") or []),
        remediation=str(doc.get("remediation", "")),
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
