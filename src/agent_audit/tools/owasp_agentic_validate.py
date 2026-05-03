# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""OWASP Top 10 for Agentic Applications validator — Roadmap item B2.

Walks every YAML rule under knowledge/rule_packs/ plus native detectors,
collects owasp_agentic:* references, and validates each against the vendored
ASI Top 10 index.

Catches three drift classes:
  - UNKNOWN: ASI ID not in the vendored OWASP Agentic Top 10
  - NAME_MISMATCH: cited title differs from upstream
  - MISSING: rule whose category has a known ASI mapping does not yet
    expose owasp_agentic in references — actionable for backfill

Same shape as owasp_mcp_validate (B1) and atlas_validate (B3) by design —
keeps the CLI surface uniform across vendored sources.

The rule-pack loader's references_rewrite mechanism applies first, so the
validator measures runtime state rather than raw YAML text. ASI version drift
(e.g. "Agent Behaviour Hijack" → "Agent Goal Hijack" in the December 2025
release) is absorbed by rewrite entries in rule_pack_overrides.yaml.

Usage:
    python -m agent_audit.tools.owasp_agentic_validate
    python -m agent_audit.tools.owasp_agentic_validate --strict
    python -m agent_audit.tools.owasp_agentic_validate --json
    python -m agent_audit.tools.owasp_agentic_validate --include-missing
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    print("ERROR: PyYAML required.", file=sys.stderr)
    sys.exit(2)


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

_PROJECT_SRC = Path(__file__).resolve().parent.parent
_RULE_PACKS_ROOT = _PROJECT_SRC / "knowledge" / "rule_packs"
_DETECTORS_ROOT = _PROJECT_SRC / "detectors"
_VENDORED_INDEX = _PROJECT_SRC / "data" / "owasp_agentic" / "owasp_agentic_top10.yaml"


# -----------------------------------------------------------------------------
# Data types
# -----------------------------------------------------------------------------

@dataclass
class AsiReference:
    asi_id: str             # e.g. "ASI03"
    cited_name: str
    source_file: Path
    raw: str


@dataclass
class AsiEntry:
    asi_id: str
    title: str
    description: str = ""


@dataclass
class ValidationIssue:
    kind: str               # "unknown" | "name_mismatch" | "missing"
    asi_id: str
    cited_name: str = ""
    actual_name: Optional[str] = None
    source_files: List[Path] = field(default_factory=list)
    details: str = ""


@dataclass
class ValidationReport:
    index_version: str
    categories_total: int
    citations_total: int
    distinct_ids_total: int
    distinct_ids_ok: int
    rules_missing_owasp_agentic: int
    issues: List[ValidationIssue]

    @property
    def has_hard_errors(self) -> bool:
        return any(i.kind == "unknown" for i in self.issues)

    @property
    def has_name_drift(self) -> bool:
        return any(i.kind == "name_mismatch" for i in self.issues)


# -----------------------------------------------------------------------------
# Loaders
# -----------------------------------------------------------------------------

# Reference format may be "ASI03" or "ASI03:2026 - Identity and Privilege Abuse"
_REF_RE = re.compile(r"^(ASI\d{1,2})(?::\d{4})?(?:\s+[-–]\s+(.+))?$")
_PY_REF_RE = re.compile(r'"owasp_agentic:(ASI\d{1,2})(?::\d{4})?(?:\s+[-–]\s+([^"]+))?"')


def load_index(path: Path) -> Tuple[str, Dict[str, AsiEntry]]:
    if not path.exists():
        raise FileNotFoundError(
            f"OWASP Agentic index not found at {path}. "
            f"See src/agent_audit/data/owasp_agentic/README.md for refresh procedure."
        )
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise ValueError(f"Malformed index at {path}")
    version = str(doc.get("version", "unknown"))
    entries: Dict[str, AsiEntry] = {}
    for e in doc.get("categories", []) or []:
        if not isinstance(e, dict) or not e.get("id"):
            continue
        entries[e["id"]] = AsiEntry(
            asi_id=e["id"],
            title=str(e.get("title", "")),
            description=str(e.get("description", "")),
        )
    return version, entries


def _infer_tool_for_rule(doc: Dict) -> str:
    """Mirror rule_pack_loader source-tool inference."""
    src = doc.get("atr_source") or doc.get("external_source") or {}
    if isinstance(src, dict) and src.get("tool"):
        return str(src["tool"])
    if "atr_source" in doc:
        return "atr"
    return "unknown"


def _walk_yaml_refs() -> Tuple[List[AsiReference], List[Tuple[Path, str, str]]]:
    """Return (refs, [(path, tool, category) for rules without owasp_agentic])."""
    # Apply same references_rewrite as runtime sees
    try:
        from ..knowledge.rule_pack_loader import _OVERRIDES_REWRITES
        agentic_rewrites = _OVERRIDES_REWRITES.get("owasp_agentic", {}) or {}
    except Exception:
        agentic_rewrites = {}

    from ..knowledge.owasp_agentic_mapping import owasp_agentic_for_pack_category

    refs: List[AsiReference] = []
    rules_without: List[Tuple[Path, str, str]] = []

    for yp in sorted(_RULE_PACKS_ROOT.rglob("*.yaml")):
        if yp.name in ("_index.yaml", "INVENTORY.yaml"):
            continue
        try:
            doc = yaml.safe_load(yp.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue

        refs_block = doc.get("references") or {}
        agentic_list = refs_block.get("owasp_agentic") or []
        for raw in agentic_list:
            s = str(raw).strip()
            # Apply override rewrites — measure runtime, not raw YAML
            s = agentic_rewrites.get(s, s)
            m = _REF_RE.match(s)
            if not m:
                continue
            refs.append(AsiReference(
                asi_id=m.group(1),
                cited_name=(m.group(2) or "").strip(),
                source_file=yp,
                raw=s,
            ))

        if not agentic_list:
            tool = _infer_tool_for_rule(doc)
            category = doc.get("category") or ""
            if tool != "unknown" and category and owasp_agentic_for_pack_category(tool, category):
                rules_without.append((yp, tool, category))

    return refs, rules_without


def _walk_python_refs() -> List[AsiReference]:
    refs: List[AsiReference] = []
    if not _DETECTORS_ROOT.exists():
        return refs
    for py in sorted(_DETECTORS_ROOT.glob("*.py")):
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in _PY_REF_RE.finditer(text):
            refs.append(AsiReference(
                asi_id=m.group(1),
                cited_name=(m.group(2) or "").strip(),
                source_file=py,
                raw=m.group(0),
            ))
    return refs


def collect_references() -> Tuple[List[AsiReference], List[Tuple[Path, str, str]]]:
    refs, rules_without = _walk_yaml_refs()
    refs.extend(_walk_python_refs())
    return refs, rules_without


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def _names_match(cited: str, actual: str) -> bool:
    if not cited:
        return True
    n_cited = re.sub(r"\s+", " ", cited.strip().lower())
    n_actual = re.sub(r"\s+", " ", actual.strip().lower())
    return n_cited == n_actual


def validate(
    references: List[AsiReference],
    index: Dict[str, AsiEntry],
    index_version: str,
    rules_without_owasp_agentic: List[Tuple[Path, str, str]],
    include_missing: bool = False,
) -> ValidationReport:
    by_id: Dict[str, List[AsiReference]] = defaultdict(list)
    for r in references:
        by_id[r.asi_id].append(r)

    issues: List[ValidationIssue] = []
    distinct_ok = 0

    for aid in sorted(by_id):
        cites = by_id[aid]
        files = sorted({c.source_file for c in cites})
        if aid not in index:
            issues.append(ValidationIssue(
                kind="unknown", asi_id=aid,
                cited_name=cites[0].cited_name,
                actual_name=None, source_files=files,
            ))
            continue
        entry = index[aid]
        cited_names = {c.cited_name for c in cites}
        any_mismatch = any(not _names_match(c, entry.title) for c in cited_names)
        if any_mismatch:
            issues.append(ValidationIssue(
                kind="name_mismatch", asi_id=aid,
                cited_name=" | ".join(sorted(cited_names)),
                actual_name=entry.title,
                source_files=files,
            ))
        else:
            distinct_ok += 1

    if include_missing:
        by_tc: Dict[Tuple[str, str], List[Path]] = defaultdict(list)
        for path, tool, category in rules_without_owasp_agentic:
            by_tc[(tool, category)].append(path)
        for (tool, category), paths in sorted(by_tc.items()):
            issues.append(ValidationIssue(
                kind="missing",
                asi_id="(none cited)",
                cited_name=f"{tool}.{category}",
                source_files=sorted(paths),
                details=f"{len(paths)} rule(s) under {tool}.{category} have a known ASI mapping but no owasp_agentic ref yet",
            ))

    return ValidationReport(
        index_version=index_version,
        categories_total=len(index),
        citations_total=len(references),
        distinct_ids_total=len(by_id),
        distinct_ids_ok=distinct_ok,
        rules_missing_owasp_agentic=len(rules_without_owasp_agentic),
        issues=issues,
    )


# -----------------------------------------------------------------------------
# Reporting
# -----------------------------------------------------------------------------

def _short_path(p: Path) -> str:
    try:
        return str(p.relative_to(_PROJECT_SRC.parent.parent))
    except ValueError:
        return str(p)


def render_text(report: ValidationReport) -> str:
    lines = []
    lines.append(f"OWASP Agentic index version: {report.index_version}")
    lines.append(f"Categories in index:         {report.categories_total}")
    lines.append(f"Citations in repo:           {report.citations_total}")
    lines.append(f"Distinct ASI IDs cited:      {report.distinct_ids_total}")
    lines.append(f"Distinct IDs OK:             {report.distinct_ids_ok}")
    lines.append(f"Rules missing owasp_agentic: {report.rules_missing_owasp_agentic}")
    lines.append(f"Issues reported:             {len(report.issues)}")
    lines.append("")

    by_kind = defaultdict(list)
    for i in report.issues:
        by_kind[i.kind].append(i)

    for kind, label in [
        ("unknown", "UNKNOWN (ASI ID not in OWASP Agentic Top 10)"),
        ("name_mismatch", "NAME MISMATCH (cited title differs from upstream)"),
        ("missing", "MISSING (mappable category, no owasp_agentic ref yet)"),
    ]:
        items = by_kind.get(kind, [])
        if not items:
            continue
        lines.append(f"{label}: {len(items)}")
        for i in items:
            if kind == "missing":
                lines.append(f"  {i.cited_name}: {i.details}")
            else:
                cited = i.cited_name or "(no name cited)"
                actual = f" — index: {i.actual_name!r}" if i.actual_name else ""
                lines.append(f"  {i.asi_id}: cited as {cited!r}{actual}")
            for f in i.source_files[:3]:
                lines.append(f"      {_short_path(f)}")
            if len(i.source_files) > 3:
                lines.append(f"      ... and {len(i.source_files) - 3} more")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(report: ValidationReport) -> str:
    obj = {
        "index_version": report.index_version,
        "categories_total": report.categories_total,
        "citations_total": report.citations_total,
        "distinct_ids_total": report.distinct_ids_total,
        "distinct_ids_ok": report.distinct_ids_ok,
        "rules_missing_owasp_agentic": report.rules_missing_owasp_agentic,
        "issues": [
            {
                "kind": i.kind,
                "asi_id": i.asi_id,
                "cited_name": i.cited_name,
                "actual_name": i.actual_name,
                "details": i.details,
                "source_files": [_short_path(f) for f in i.source_files],
            }
            for i in report.issues
        ],
    }
    return json.dumps(obj, indent=2)


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(
        prog="agent-audit-owasp-agentic-validate",
        description=__doc__.split("\n\n")[0],
    )
    p.add_argument("--index", type=Path, default=_VENDORED_INDEX)
    p.add_argument("--strict", action="store_true",
                   help="Exit 1 on ANY issue (including name drift). Default exits 1 only on unknown IDs.")
    p.add_argument("--include-missing", action="store_true",
                   help="Also list rules with mappable category but no explicit owasp_agentic ref (informational, never affects exit code).")
    p.add_argument("--json", dest="as_json", action="store_true")
    p.add_argument("--quiet", action="store_true")
    args = p.parse_args(argv)

    try:
        version, index = load_index(args.index)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR loading OWASP Agentic index: {exc}", file=sys.stderr)
        return 2

    refs, rules_without = collect_references()
    report = validate(refs, index, version, rules_without, include_missing=args.include_missing)

    if not args.quiet:
        if args.as_json:
            print(render_json(report))
        else:
            print(render_text(report))

    if report.has_hard_errors:
        return 1
    if args.strict and report.has_name_drift:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
