# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""AVID reference validator — Rules Expansion Roadmap item B4.

Walks every loaded rule (the runtime view, after references_rewrite has
applied), collects avid:* references, and validates each against the
canonical SEP subcategory list in knowledge/avid_mapping.py.

Catches three drift classes:
  - UNKNOWN: the SEP ID is not in upstream avidtools.SepEnum
  - MISSING: a rule whose (tool, category) has a known AVID mapping
    has no avid: reference yet — actionable for backfill
  - NAME_MISMATCH: cited SEP title no longer matches upstream

Mirrors atlas_validate (B3), owasp_mcp_validate (B1), and
owasp_agentic_validate (B2) by design — keeps the CLI surface uniform
across reference taxonomies.

Why no vendored snapshot file: the AVID schema is small (48 SEP
subcategories) and rarely changes; we keep the canonical labels inline
in `avid_mapping._SEP_LABELS`. If upstream renames a category, fix the
label there and add a `references_rewrite` entry for absorbing the
old name in existing YAMLs.

Usage:
    python -m agent_audit.tools.avid_validate
    python -m agent_audit.tools.avid_validate --strict
    python -m agent_audit.tools.avid_validate --json
    python -m agent_audit.tools.avid_validate --include-missing
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple


_SEP_ID_RE = re.compile(r"\b([SEP])(\d{4})\b")


# -----------------------------------------------------------------------------
# Data types
# -----------------------------------------------------------------------------

@dataclass
class AvidReference:
    sep_id: str           # "S0301"
    cited_name: str       # what the YAML / runtime reference cites
    rule_id: str
    raw: str


@dataclass
class ValidationIssue:
    kind: str             # "unknown" | "name_mismatch" | "missing"
    sep_id: str
    cited_name: str = ""
    expected_name: str = ""
    rule_id: str = ""

    def to_dict(self) -> dict:
        return {
            "kind": self.kind,
            "sep_id": self.sep_id,
            "cited_name": self.cited_name,
            "expected_name": self.expected_name,
            "rule_id": self.rule_id,
        }


@dataclass
class ValidationReport:
    total_rules: int = 0
    rules_with_avid: int = 0
    refs_total: int = 0
    refs_unique_ids: int = 0
    unknown: List[ValidationIssue] = field(default_factory=list)
    name_mismatch: List[ValidationIssue] = field(default_factory=list)
    missing: List[ValidationIssue] = field(default_factory=list)

    @property
    def has_hard_errors(self) -> bool:
        return bool(self.unknown)

    @property
    def has_any_issues(self) -> bool:
        return bool(self.unknown or self.name_mismatch)

    def to_dict(self) -> dict:
        return {
            "total_rules": self.total_rules,
            "rules_with_avid": self.rules_with_avid,
            "refs_total": self.refs_total,
            "refs_unique_ids": self.refs_unique_ids,
            "unknown": [i.to_dict() for i in self.unknown],
            "name_mismatch": [i.to_dict() for i in self.name_mismatch],
            "missing": [i.to_dict() for i in self.missing],
        }


# -----------------------------------------------------------------------------
# Reference parsing
# -----------------------------------------------------------------------------

def _parse_avid_ref(text: str) -> Optional[Tuple[str, str]]:
    """Extract (sep_id, full_text) from a single avid reference string.

    Accepts canonical "S0301: Information Leak" form and bare-ID
    "S0301" form. Returns the full text as the second tuple element so
    callers can compare it against the expected canonical label
    "Sxxxx: Title" form rather than stripping the prefix and losing
    the comparison.
    """
    if not text:
        return None
    m = _SEP_ID_RE.search(text)
    if not m:
        return None
    sep_id = m.group(0)
    return sep_id, text.strip()


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def validate(*, include_missing: bool = False) -> ValidationReport:
    """Run validation against currently-loaded rule packs.

    The loader's enrichment pass populates `references["avid"]`
    automatically for every rule whose (tool, category) has a known
    mapping. We measure the runtime state, not raw YAML — that's what
    actually flows into reports and what end-users see.
    """
    from ..knowledge.rule_pack_loader import load_all_rules
    from ..knowledge.avid_mapping import (
        _SEP_LABELS,
        all_mapped_pack_keys,
        avid_for_pack_category,
        avid_label,
    )

    report = ValidationReport()
    rules = load_all_rules(static_only=False)
    report.total_rules = len(rules)

    seen_ids: set = set()

    for rule in rules:
        avid_refs = rule.references.get("avid") or []
        if not isinstance(avid_refs, list):
            continue
        if avid_refs:
            report.rules_with_avid += 1
        for raw in avid_refs:
            parsed = _parse_avid_ref(str(raw))
            if not parsed:
                continue
            sep_id, cited = parsed
            seen_ids.add(sep_id)
            report.refs_total += 1

            expected = _SEP_LABELS.get(sep_id)
            if expected is None:
                report.unknown.append(ValidationIssue(
                    kind="unknown", sep_id=sep_id,
                    cited_name=cited,
                    rule_id=rule.agent_audit_id,
                ))
                continue
            # If cited text is just the bare ID, that's fine — no
            # title was claimed, nothing to drift from. Only flag
            # mismatch when the cited form differs from the canonical
            # "Sxxxx: Title" label.
            if cited != sep_id and cited != expected:
                report.name_mismatch.append(ValidationIssue(
                    kind="name_mismatch", sep_id=sep_id,
                    cited_name=cited,
                    expected_name=expected,
                    rule_id=rule.agent_audit_id,
                ))

    report.refs_unique_ids = len(seen_ids)

    # MISSING pass — informational only. A rule is "missing" AVID
    # references if its (source_tool, category) has a known mapping but
    # the loader's enrichment didn't kick in for some reason (e.g. the
    # YAML pre-declared an empty `references.avid` block). With our
    # current loader pattern this never happens, but the check guards
    # against future regressions.
    if include_missing:
        for rule in rules:
            if rule.references.get("avid"):
                continue
            mapping = avid_for_pack_category(rule.source_tool, rule.category)
            if not mapping:
                continue
            for sep_id in mapping:
                report.missing.append(ValidationIssue(
                    kind="missing", sep_id=sep_id,
                    expected_name=avid_label(sep_id) or sep_id,
                    rule_id=rule.agent_audit_id,
                ))

    return report


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="avid-validate", description=__doc__.split("\n\n")[0])
    p.add_argument("--strict", action="store_true",
                   help="Exit 1 on ANY issue, including name drift.")
    p.add_argument("--include-missing", action="store_true",
                   help="Report rules whose category has a mapping but no "
                        "avid: reference. Informational; never affects exit.")
    p.add_argument("--json", action="store_true", dest="as_json",
                   help="Emit JSON instead of text.")
    p.add_argument("--quiet", action="store_true",
                   help="Print nothing; rely on exit code.")
    args = p.parse_args(argv)

    report = validate(include_missing=args.include_missing)

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    elif not args.quiet:
        _emit_text(report)

    if args.strict:
        return 1 if report.has_any_issues else 0
    return 1 if report.has_hard_errors else 0


def _emit_text(report: ValidationReport) -> None:
    print(f"AVID reference validation")
    print(f"=" * 60)
    print(f"  Rules total:              {report.total_rules}")
    print(f"  Rules with AVID refs:     {report.rules_with_avid}")
    print(f"  Total avid: references:   {report.refs_total}")
    print(f"  Unique SEP IDs cited:     {report.refs_unique_ids}")
    print()
    if report.unknown:
        print(f"UNKNOWN ({len(report.unknown)}):")
        for issue in report.unknown[:10]:
            print(f"  {issue.sep_id} [{issue.rule_id}]: cited={issue.cited_name!r}")
        if len(report.unknown) > 10:
            print(f"  ... +{len(report.unknown) - 10} more")
        print()
    if report.name_mismatch:
        print(f"NAME_MISMATCH ({len(report.name_mismatch)}):")
        for issue in report.name_mismatch[:10]:
            print(f"  {issue.sep_id} [{issue.rule_id}]")
            print(f"    cited:    {issue.cited_name!r}")
            print(f"    expected: {issue.expected_name!r}")
        if len(report.name_mismatch) > 10:
            print(f"  ... +{len(report.name_mismatch) - 10} more")
        print()
    if report.missing:
        print(f"MISSING ({len(report.missing)}, informational):")
        for issue in report.missing[:10]:
            print(f"  {issue.rule_id}: would map to {issue.sep_id}")
        if len(report.missing) > 10:
            print(f"  ... +{len(report.missing) - 10} more")
        print()
    if not report.has_any_issues and not report.missing:
        print("OK — no issues.")


if __name__ == "__main__":
    sys.exit(main())
