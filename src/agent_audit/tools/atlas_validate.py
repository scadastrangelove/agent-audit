# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""MITRE ATLAS reference validator — Rules Expansion Roadmap item B3.

Walks every YAML rule under knowledge/rule_packs/ plus native detectors,
collects mitre_atlas:* references, and validates each against an
upstream ATLAS data snapshot.

Catches three drift classes:
  - UNKNOWN: the technique ID does not exist in ATLAS at all
  - DEPRECATED: ATLAS marked the technique deprecated/superseded
  - NAME_MISMATCH: the cited name no longer matches ATLAS (e.g. ATLAS
    renamed "ML Supply Chain Compromise" to "AI Supply Chain Compromise"
    in the AI/ML wording sweep)

Usage:
    # vendor a snapshot of mitre-atlas/atlas-data ATLAS.yaml under data/
    python -m agent_audit.tools.atlas_validate

    # or point at a custom location
    python -m agent_audit.tools.atlas_validate --atlas /path/to/ATLAS.yaml

    # CI-friendly: exit 1 if anything is unknown/deprecated, ignore name drift
    python -m agent_audit.tools.atlas_validate --strict

    # JSON output for CI integration
    python -m agent_audit.tools.atlas_validate --json

Vendoring policy:
The repository ships a snapshot of dist/ATLAS.yaml under
src/agent_audit/data/atlas/ATLAS.yaml refreshed quarterly. ATLAS data is
Apache-2.0; license file lives next to the snapshot. The validator reads
the vendored copy by default — no network at run time.

Refresh procedure (manual, quarterly):
    git clone --depth 1 https://github.com/mitre-atlas/atlas-data.git /tmp/atlas-data
    cp /tmp/atlas-data/dist/ATLAS.yaml \\
       src/agent_audit/data/atlas/ATLAS.yaml
    # update version comment in this docstring
    python -m agent_audit.tools.atlas_validate --strict
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
    print("ERROR: PyYAML required. pip install pyyaml", file=sys.stderr)
    sys.exit(2)


# -----------------------------------------------------------------------------
# Paths
# -----------------------------------------------------------------------------

# Relative to this file: src/agent_audit/tools/atlas_validate.py
_PROJECT_SRC = Path(__file__).resolve().parent.parent
_RULE_PACKS_ROOT = _PROJECT_SRC / "knowledge" / "rule_packs"
_DETECTORS_ROOT = _PROJECT_SRC / "detectors"
_VENDORED_ATLAS = _PROJECT_SRC / "data" / "atlas" / "ATLAS.yaml"


# -----------------------------------------------------------------------------
# Data types
# -----------------------------------------------------------------------------

@dataclass
class AtlasReference:
    """One mitre_atlas: reference cited in our codebase."""
    technique_id: str            # "AML.T0051" or "AML.T0051.001"
    cited_name: str              # name as written in our YAML, may be ""
    source_file: Path            # where we found it
    raw: str                     # raw string for display


@dataclass
class AtlasTechnique:
    """One technique loaded from upstream ATLAS data."""
    technique_id: str
    name: str
    is_subtechnique: bool
    parent_id: Optional[str] = None
    deprecated: bool = False
    revoked: bool = False


@dataclass
class ValidationIssue:
    kind: str                    # "unknown" | "deprecated" | "name_mismatch"
    technique_id: str
    cited_name: str
    actual_name: Optional[str]
    source_files: List[Path] = field(default_factory=list)


@dataclass
class ValidationReport:
    atlas_version: str
    techniques_total: int
    citations_total: int
    distinct_ids_total: int
    distinct_ids_ok: int
    issues: List[ValidationIssue]

    @property
    def has_hard_errors(self) -> bool:
        return any(i.kind in ("unknown", "deprecated") for i in self.issues)

    @property
    def has_name_drift(self) -> bool:
        return any(i.kind == "name_mismatch" for i in self.issues)


# -----------------------------------------------------------------------------
# Loaders
# -----------------------------------------------------------------------------

# Matches "AML.TNNNN" or "AML.TNNNN.NNN" optionally followed by " - Name"
_REF_RE = re.compile(r"^(AML\.[A-Z]?\d+(?:\.\d+)?)(?:\s+[-–]\s+(.+))?$")
# For scanning Python detector source code: we expect the "mitre_atlas:..." form
# inside string literals
_PY_REF_RE = re.compile(r'"mitre_atlas:(AML\.[A-Z]?\d+(?:\.\d+)?)(?:\s+[-–]\s+([^"]+))?"')


def load_atlas(path: Path) -> Tuple[str, Dict[str, AtlasTechnique]]:
    """Parse ATLAS.yaml and return (version, {id: technique})."""
    if not path.exists():
        raise FileNotFoundError(
            f"ATLAS snapshot not found at {path}. "
            f"Run the refresh procedure documented in the module docstring."
        )
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    version = str(doc.get("version", "unknown"))
    matrices = doc.get("matrices") or []
    if not matrices:
        raise ValueError(f"No matrices in {path}")
    techs_raw = matrices[0].get("techniques") or []
    techs: Dict[str, AtlasTechnique] = {}
    for t in techs_raw:
        tid = t.get("id")
        if not tid:
            continue
        parent = t.get("subtechnique-of")
        techs[tid] = AtlasTechnique(
            technique_id=tid,
            name=str(t.get("name", "")),
            is_subtechnique=bool(parent),
            parent_id=parent,
            deprecated=bool(t.get("deprecated") or t.get("x_mitre_deprecated")),
            revoked=bool(t.get("revoked")),
        )
    return version, techs


def _walk_yaml_refs() -> List[AtlasReference]:
    """Extract every mitre_atlas: ref from rule-pack YAMLs.

    Applies the global text rewrites from rule_pack_overrides.yaml so the
    validator measures the runtime state of references — which is what
    rule-pack consumers actually see. A rewrite that fixes upstream drift
    means that drift is no longer a problem in practice.
    """
    # Lazy import to avoid circular dependency
    try:
        from ..knowledge.rule_pack_loader import _OVERRIDES_REWRITES
        atlas_rewrites = _OVERRIDES_REWRITES.get("mitre_atlas", {}) or {}
    except Exception:
        atlas_rewrites = {}

    refs: List[AtlasReference] = []
    for yp in sorted(_RULE_PACKS_ROOT.rglob("*.yaml")):
        if yp.name in ("_index.yaml", "INVENTORY.yaml"):
            continue
        try:
            doc = yaml.safe_load(yp.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            continue
        if not isinstance(doc, dict):
            continue
        atlas_list = ((doc.get("references") or {}).get("mitre_atlas") or [])
        for raw in atlas_list:
            s = str(raw).strip()
            # Apply override rewrite first — measure runtime, not YAML
            s = atlas_rewrites.get(s, s)
            m = _REF_RE.match(s)
            if not m:
                continue
            refs.append(AtlasReference(
                technique_id=m.group(1),
                cited_name=(m.group(2) or "").strip(),
                source_file=yp,
                raw=s,
            ))
    return refs


def _walk_python_refs() -> List[AtlasReference]:
    """Extract mitre_atlas: refs from native detector Python source."""
    refs: List[AtlasReference] = []
    if not _DETECTORS_ROOT.exists():
        return refs
    for py in sorted(_DETECTORS_ROOT.glob("*.py")):
        try:
            text = py.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in _PY_REF_RE.finditer(text):
            refs.append(AtlasReference(
                technique_id=m.group(1),
                cited_name=(m.group(2) or "").strip(),
                source_file=py,
                raw=m.group(0),
            ))
    return refs


def collect_references() -> List[AtlasReference]:
    """All mitre_atlas: citations in the codebase."""
    return _walk_yaml_refs() + _walk_python_refs()


# -----------------------------------------------------------------------------
# Validation
# -----------------------------------------------------------------------------

def _names_match(cited: str, actual: str) -> bool:
    """Lenient comparison: case-insensitive, whitespace-collapsed."""
    if not cited:
        # Empty cited name = ID-only reference, no name to mismatch
        return True
    norm_cited = re.sub(r"\s+", " ", cited.strip().lower())
    norm_actual = re.sub(r"\s+", " ", actual.strip().lower())
    return norm_cited == norm_actual


def validate(
    references: List[AtlasReference],
    atlas_techs: Dict[str, AtlasTechnique],
    atlas_version: str,
) -> ValidationReport:
    # Group references by technique_id
    by_id: Dict[str, List[AtlasReference]] = defaultdict(list)
    for r in references:
        by_id[r.technique_id].append(r)

    issues: List[ValidationIssue] = []
    distinct_ok = 0

    for tid in sorted(by_id):
        cites = by_id[tid]
        files = sorted({c.source_file for c in cites})
        if tid not in atlas_techs:
            issues.append(ValidationIssue(
                kind="unknown",
                technique_id=tid,
                cited_name=cites[0].cited_name,
                actual_name=None,
                source_files=files,
            ))
            continue
        atech = atlas_techs[tid]
        if atech.deprecated or atech.revoked:
            issues.append(ValidationIssue(
                kind="deprecated",
                technique_id=tid,
                cited_name=cites[0].cited_name,
                actual_name=atech.name,
                source_files=files,
            ))
            continue
        # Check every distinct cited name we have for this id
        cited_names = {c.cited_name for c in cites}
        any_mismatch = False
        for cited in cited_names:
            if not _names_match(cited, atech.name):
                any_mismatch = True
                break
        if any_mismatch:
            issues.append(ValidationIssue(
                kind="name_mismatch",
                technique_id=tid,
                cited_name=" | ".join(sorted(cited_names)),
                actual_name=atech.name,
                source_files=files,
            ))
        else:
            distinct_ok += 1

    return ValidationReport(
        atlas_version=atlas_version,
        techniques_total=len(atlas_techs),
        citations_total=len(references),
        distinct_ids_total=len(by_id),
        distinct_ids_ok=distinct_ok,
        issues=issues,
    )


# -----------------------------------------------------------------------------
# Reporting
# -----------------------------------------------------------------------------

def _short_path(p: Path) -> str:
    """Display path relative to project root when possible."""
    try:
        return str(p.relative_to(_PROJECT_SRC.parent.parent))
    except ValueError:
        return str(p)


def render_text(report: ValidationReport) -> str:
    lines = []
    lines.append(f"ATLAS version:        {report.atlas_version}")
    lines.append(f"ATLAS techniques:     {report.techniques_total}")
    lines.append(f"Citations in repo:    {report.citations_total}")
    lines.append(f"Distinct IDs cited:   {report.distinct_ids_total}")
    lines.append(f"Distinct IDs OK:      {report.distinct_ids_ok}")
    lines.append(f"Issues:               {len(report.issues)}")
    lines.append("")

    by_kind = defaultdict(list)
    for i in report.issues:
        by_kind[i.kind].append(i)

    for kind, label in [
        ("unknown", "UNKNOWN (technique ID not in ATLAS)"),
        ("deprecated", "DEPRECATED (technique deprecated or revoked)"),
        ("name_mismatch", "NAME MISMATCH (cited name differs from ATLAS)"),
    ]:
        items = by_kind.get(kind, [])
        if not items:
            continue
        lines.append(f"{label}: {len(items)}")
        for i in items:
            cited = i.cited_name or "(no name cited)"
            actual = f" — ATLAS: {i.actual_name!r}" if i.actual_name else ""
            lines.append(f"  {i.technique_id}: cited as {cited!r}{actual}")
            for f in i.source_files[:3]:
                lines.append(f"      {_short_path(f)}")
            if len(i.source_files) > 3:
                lines.append(f"      ... and {len(i.source_files) - 3} more")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render_json(report: ValidationReport) -> str:
    obj = {
        "atlas_version": report.atlas_version,
        "atlas_techniques_total": report.techniques_total,
        "citations_total": report.citations_total,
        "distinct_ids_total": report.distinct_ids_total,
        "distinct_ids_ok": report.distinct_ids_ok,
        "issues": [
            {
                "kind": i.kind,
                "technique_id": i.technique_id,
                "cited_name": i.cited_name,
                "actual_name": i.actual_name,
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
        prog="agent-audit-atlas-validate",
        description=__doc__.split("\n\n")[0],
    )
    p.add_argument(
        "--atlas",
        type=Path,
        default=_VENDORED_ATLAS,
        help=f"Path to ATLAS.yaml (default: vendored snapshot at {_VENDORED_ATLAS})",
    )
    p.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 on ANY issue (including name drift). Default exits 1 only "
             "on unknown/deprecated IDs.",
    )
    p.add_argument(
        "--json",
        action="store_true",
        help="Emit JSON instead of text report.",
    )
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Print nothing to stdout; rely on exit code only.",
    )
    args = p.parse_args(argv)

    try:
        version, techs = load_atlas(args.atlas)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as exc:
        print(f"ERROR loading ATLAS data: {exc}", file=sys.stderr)
        return 2

    refs = collect_references()
    if not refs:
        if not args.quiet:
            print("No mitre_atlas: references found in this codebase.")
        return 0

    report = validate(refs, techs, version)

    if not args.quiet:
        if args.json:
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
