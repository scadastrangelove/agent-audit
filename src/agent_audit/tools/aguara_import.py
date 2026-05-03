# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Aguara rule-pack importer — Roadmap item A1.

Converts upstream Aguara YAML (multi-doc) into our per-rule YAML files
under src/agent_audit/knowledge/rule_packs/external/aguara/.

Upstream format (one file per category, multiple rules):
    id: EXTDL_001
    name: "Runtime URL controls agent behavior"
    description: "..."
    severity: HIGH
    category: external-download
    targets: ["*.md", "*.txt"]
    match_mode: all
    patterns:
      - type: regex
        value: ...
    examples:
      true_positive: [...]
      false_positive: [...]

Our format (one file per rule, with attribution + ASAMM mapping):
    external_source:
      tool: aguara
      original_id: EXTDL_001
      ...
    agent_audit_id: aguara.external-download.runtime-url-controls-agent-behavior
    title: Runtime URL controls agent behavior
    severity_default: high
    category: external-download
    audit_surface: [instruction_file, skill_md]
    asamm:
      primary: ...
      secondary: [...]
    patterns: [...]
    exclude_patterns: []

Usage:
    python -m agent_audit.tools.aguara_import \\
        --source /tmp/aguara/internal/rules/builtin \\
        --upstream-sha <git-sha> \\
        [--dry-run]

Convention: keep this script idempotent. Re-running on the same upstream
SHA produces byte-identical output. The wholesale-replace approach is
safer than per-rule diff merging because Aguara's IDs are stable, and
the mapping below covers every category.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


_DEFAULT_DEST = (
    Path(__file__).resolve().parent.parent
    / "knowledge" / "rule_packs" / "external" / "aguara"
)


# ----------------------------------------------------------------------------
# Category metadata — ASAMM mapping + audit_surface defaults
# ----------------------------------------------------------------------------

# Each Aguara category maps to:
#   asamm.primary, asamm.secondary
#   audit_surface defaults
# These are category-level defaults. Per-rule review may override later via
# rule_pack_overrides.yaml.
#
# ASAMM glossary used:
#   AI-03 — context exfiltration
#   AI-04 — persistent identity rewrite
#   AI-05 — identity redefinition language
#   AD-02 — broad action without approval
#   AD-04 — autonomous fetch / install
#   AG-02 — agent guardrail bypass
#   AG-03 — credential / secret exposure
#   AG-04 — supply-chain compromise
#   AG-05 — runtime composition compromise
#
# Where multiple ASAMM IDs apply, we list the strongest fit first.
_CATEGORY_META: Dict[str, Dict] = {
    "external-download": {
        "asamm_primary": "AG-02",
        "asamm_secondary": ["AI-03", "AD-04"],
        "audit_surface": ["instruction_file", "skill_md"],
    },
    "ssrf-cloud": {
        "asamm_primary": "AG-04",
        "asamm_secondary": ["AD-04"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "third-party-content": {
        "asamm_primary": "AI-03",
        "asamm_secondary": ["AG-02"],
        "audit_surface": ["instruction_file", "skill_md"],
    },
    # New categories from the 37→189 jump
    "command-execution": {
        "asamm_primary": "AD-02",
        "asamm_secondary": ["AG-02", "AD-04"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "credential-leak": {
        "asamm_primary": "AG-03",
        "asamm_secondary": ["AI-03"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description", "mcp_manifest"],
    },
    "exfiltration": {
        "asamm_primary": "AI-03",
        "asamm_secondary": ["AG-03"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "indirect-injection": {
        "asamm_primary": "AI-04",
        "asamm_secondary": ["AI-05", "AI-03"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "mcp-attack": {
        "asamm_primary": "AG-04",
        "asamm_secondary": ["AG-05", "AI-04"],
        "audit_surface": ["mcp_manifest", "tool_description"],
    },
    "mcp-config": {
        "asamm_primary": "AG-04",
        "asamm_secondary": ["AG-03"],
        "audit_surface": ["mcp_manifest"],
    },
    "prompt-injection": {
        "asamm_primary": "AI-04",
        "asamm_secondary": ["AI-05"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "supply-chain": {
        "asamm_primary": "AG-04",
        "asamm_secondary": ["AD-04"],
        "audit_surface": ["instruction_file", "skill_md", "mcp_manifest", "plugin_manifest"],
    },
    "supply-chain-exfil": {
        "asamm_primary": "AI-03",
        "asamm_secondary": ["AG-04", "AG-03"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "unicode-attack": {
        "asamm_primary": "AI-04",
        "asamm_secondary": ["AG-02"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description", "mcp_manifest"],
    },
}


# ----------------------------------------------------------------------------
# Slug helpers
# ----------------------------------------------------------------------------

def _slugify(name: str, max_len: int = 60) -> str:
    """Convert a rule name into a kebab-case slug suitable for filenames."""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    if len(s) > max_len:
        # Cut at word boundary
        s = s[:max_len].rsplit("-", 1)[0]
    return s or "rule"


def _agent_audit_id(category: str, slug: str) -> str:
    return f"aguara.{category}.{slug}"


def _filename_for(original_id: str, slug: str) -> str:
    return f"{original_id}-{slug}.yaml"


# ----------------------------------------------------------------------------
# Conversion
# ----------------------------------------------------------------------------

def _normalize_severity(s: str) -> str:
    s = (s or "medium").strip().lower()
    return s if s in ("low", "medium", "high", "critical") else "medium"


def _convert_rule(rule: Dict, category: str, upstream_sha: str) -> Optional[Dict]:
    """Convert one upstream rule dict to our format. Returns None on malformed input."""
    rid = rule.get("id")
    name = rule.get("name") or rule.get("title", "")
    if not rid or not name:
        return None

    meta = _CATEGORY_META.get(category)
    if meta is None:
        # Unknown category — skip with a warning. Refuse to invent ASAMM mapping.
        print(f"WARNING: unmapped category {category!r} for rule {rid}; skipping",
              file=sys.stderr)
        return None

    slug = _slugify(name)
    severity = _normalize_severity(rule.get("severity", ""))

    converted = {
        "external_source": {
            "tool": "aguara",
            "original_id": rid,
            "original_title": name,
            "source_version": f"git-{upstream_sha[:12]}",
            "import_date": date.today().isoformat(),
            "upstream": "https://github.com/garagon/aguara",
            "license": "Apache-2.0 (c) 2026 garagon",
        },
        "agent_audit_id": _agent_audit_id(category, slug),
        "title": name,
        "description": str(rule.get("description", "")).strip(),
        "severity_default": severity,
        "category": category,
        "audit_surface": list(meta["audit_surface"]),
        "asamm": {
            "primary": meta["asamm_primary"],
            "secondary": list(meta["asamm_secondary"]),
            "mapping_confidence": "category-default",
            "notes": "Category-level default at import. Review per rule.",
        },
    }

    # Optional fields
    targets = rule.get("targets")
    if targets:
        converted["targets"] = list(targets)

    match_mode = rule.get("match_mode")
    if match_mode:
        converted["match_mode"] = str(match_mode)

    # Patterns: copy as-is. The rule_pack_loader handles the {type, value} shape.
    patterns = rule.get("patterns") or []
    converted["patterns"] = list(patterns)

    # We always emit exclude_patterns, possibly empty, for shape consistency
    converted["exclude_patterns"] = list(rule.get("exclude_patterns") or [])

    remediation = rule.get("remediation")
    if remediation:
        converted["remediation"] = str(remediation).strip()

    examples = rule.get("examples")
    if examples and isinstance(examples, dict):
        converted["examples"] = examples

    return converted


def _header_comment(rule: Dict) -> str:
    """Generate the comment block at the top of each YAML file."""
    aaid = rule["agent_audit_id"]
    src = rule["external_source"]
    rid = src["original_id"]
    sev = rule["severity_default"]
    asamm = rule["asamm"]
    asamm_str = asamm["primary"]
    if asamm["secondary"]:
        asamm_str += f" (+{','.join(asamm['secondary'])})"
    return (
        "# " + ("=" * 61) + "\n"
        f"# {aaid}\n"
        "# " + ("=" * 61) + "\n"
        f"# Adapted from {rid} (https://github.com/garagon/aguara)\n"
        "# Apache-2.0 (c) 2026 garagon\n"
        "# Source: Aguara\n"
        f"# Severity: {sev}  |  ASAMM: {asamm_str}\n"
        "# " + ("=" * 61) + "\n"
    )


def _emit_yaml_file(rule: Dict, dest: Path) -> None:
    """Write one converted rule to disk as a YAML file."""
    header = _header_comment(rule)
    body = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
    dest.write_text(header + body, encoding="utf-8")


# ----------------------------------------------------------------------------
# Top-level import
# ----------------------------------------------------------------------------

def import_pack(source_dir: Path, dest_dir: Path, upstream_sha: str,
                dry_run: bool = False) -> Dict[str, int]:
    """Replace dest_dir contents with converted rules from source_dir.

    Returns counts {category: rule_count, "total": N}.
    """
    if not source_dir.exists():
        raise FileNotFoundError(f"Aguara source dir not found: {source_dir}")

    yaml_files = sorted(source_dir.glob("*.yaml"))
    if not yaml_files:
        raise ValueError(f"No YAML files found in {source_dir}")

    # Collect all rules first, abort early on errors
    by_category: Dict[str, List[Dict]] = {}
    skipped = 0
    for yp in yaml_files:
        text = yp.read_text(encoding="utf-8")
        try:
            docs = list(yaml.safe_load_all(text))
        except yaml.YAMLError as e:
            print(f"WARNING: skipping malformed file {yp.name}: {e}", file=sys.stderr)
            continue
        for d in docs:
            if not d or not isinstance(d, dict):
                continue
            category = d.get("category", "")
            converted = _convert_rule(d, category, upstream_sha)
            if converted is None:
                skipped += 1
                continue
            by_category.setdefault(category, []).append(converted)

    if not by_category:
        raise ValueError("No rules converted — aborting")

    # Wholesale replace dest_dir to avoid stale files from previous imports
    if not dry_run:
        if dest_dir.exists():
            for child in dest_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        dest_dir.mkdir(parents=True, exist_ok=True)

    counts = {}
    for category, rules in sorted(by_category.items()):
        cat_dir = dest_dir / category
        if not dry_run:
            cat_dir.mkdir(exist_ok=True)
        for rule in rules:
            slug = rule["agent_audit_id"].rsplit(".", 1)[1]
            fname = _filename_for(rule["external_source"]["original_id"], slug)
            if not dry_run:
                _emit_yaml_file(rule, cat_dir / fname)
        counts[category] = len(rules)

    counts["__total__"] = sum(counts.values())
    counts["__skipped__"] = skipped
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="aguara-import", description=__doc__.split("\n\n")[0])
    p.add_argument("--source", type=Path, required=True,
                   help="Path to upstream Aguara internal/rules/builtin/ directory")
    p.add_argument("--upstream-sha", type=str, required=True,
                   help="Git SHA of upstream snapshot for source_version field")
    p.add_argument("--dest", type=Path, default=_DEFAULT_DEST,
                   help=f"Destination dir (default: {_DEFAULT_DEST})")
    p.add_argument("--dry-run", action="store_true",
                   help="Parse and report counts without writing files")
    args = p.parse_args(argv)

    try:
        counts = import_pack(args.source, args.dest, args.upstream_sha, args.dry_run)
    except (FileNotFoundError, ValueError) as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    total = counts.pop("__total__")
    skipped = counts.pop("__skipped__", 0)
    label = "[DRY RUN] " if args.dry_run else ""
    print(f"{label}Imported {total} rules across {len(counts)} categories:")
    for cat in sorted(counts):
        print(f"  {cat:25} {counts[cat]:3}")
    if skipped:
        print(f"\nSkipped {skipped} rules due to unmapped categories or malformed YAML")
    return 0


if __name__ == "__main__":
    sys.exit(main())
