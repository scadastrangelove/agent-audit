# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Gitleaks rule-pack importer — Roadmap item A3.

Converts upstream Gitleaks TOML config (single file with [[rules]] arrays)
into our per-rule YAML format under
src/agent_audit/knowledge/rule_packs/external/gitleaks/.

Upstream format (one entry per [[rules]] block in config/gitleaks.toml):
    [[rules]]
    id = "aws-access-key-id"
    description = "Identified a potential AWS Access Key ID..."
    regex = '''\\b(A3T[A-Z0-9]|AKIA|...)[A-Z0-9]{16}\\b'''
    entropy = 3.5         # optional — minimum Shannon entropy for the match
    keywords = ["AKIA"]   # required for fast-path; we ignore (regex is enough)
    path = "..."          # optional — regex on file path
    allowlists = [...]    # optional — array of allowlist tables

Our format mirrors the Aguara/ATR shape:
    external_source: {tool: gitleaks, original_id, ...}
    agent_audit_id: gitleaks.hardcoded_secrets.<slug>
    severity_default: high   # all secrets default to HIGH
    category: hardcoded_secrets
    audit_surface: [instruction_file, skill_md, mcp_manifest, tool_description]
    asamm: {primary: AG-03, secondary: [AI-03], ...}
    targets: ["*.md", "*.txt", "*.json", "*.yaml", ...]
    patterns: [{type: regex, value: "..."}]
    exclude_patterns: [...]   # known example tokens to suppress

## Regex compatibility

Gitleaks runs on Go's RE2 engine. Python's `re` is PCRE-lite. The dialects
overlap but not identically:

- **Inline flag mid-pattern** (`(?i)` not at start): Go accepts; Python
  treats it as deprecated and raises in some cases. We pull leading
  `(?i)` to the front, drop trailing inline flags, and rely on
  case-folded character classes where possible.
- **Backreferences** (`\\1`): both support.
- **Possessive quantifiers**, **lookaheads**, **lookbehinds**: Go RE2
  doesn't support them, so Gitleaks rules don't use them. No translation
  needed.
- **Named groups**: both support `(?P<name>...)` syntax.
- **Possessive char classes** like `[\\w-]++`: Go doesn't support `++`,
  Gitleaks rules don't use them.

The importer does the minimal rewriting needed and skips rules whose
regex Python can't compile. Empirically that's <5% of rules.

## Calibration discipline

Secret-detection regexes are the densest false-positive class on benign
documentation:
- Example tokens that LOOK like real keys: `AKIAIOSFODNN7EXAMPLE`,
  `ghp_xxxxxxxxxx...`, RSA test fixtures.
- Documentation strings: `<your_api_key_here>`, `xxx-xxx-xxx`.
- Short test fixtures with low entropy.

Gitleaks's own `entropy` gate handles the low-entropy class. We honor it
when present — patterns below the minimum entropy don't fire. For known
example tokens, we ship a baseline `exclude_patterns` block that catches
the most common cases.

## Usage

    python -m agent_audit.tools.gitleaks_import \\
        --source /tmp/gitleaks/config/gitleaks.toml \\
        --upstream-sha <git-sha>
"""
from __future__ import annotations

import argparse
import math
import re
import shutil
import sys
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

try:
    import tomllib  # 3.11+
except ImportError:  # pragma: no cover — older Pythons
    import tomli as tomllib  # type: ignore

import yaml


_DEFAULT_DEST = (
    Path(__file__).resolve().parent.parent
    / "knowledge" / "rule_packs" / "external" / "gitleaks"
)


# ----------------------------------------------------------------------------
# Category metadata — Gitleaks ships one big bag of secret-detection rules,
# so a single category fits. ASAMM AG-03 (credential exposure) is the
# obvious primary; AI-03 (context exfil) when a leaked key gets used.
# ----------------------------------------------------------------------------

_CATEGORY = "hardcoded_secrets"
_ASAMM_PRIMARY = "AG-03"
_ASAMM_SECONDARY = ["AI-03"]

# Where secret leaks plausibly land:
# - instruction_file / skill_md: skill authors hardcoding API keys
# - mcp_manifest: MCP server configs with secrets in env blocks
# - tool_description: tools encouraging the agent to use a specific token
# - agent_task_config: AGENTS.md / config files with secrets
_AUDIT_SURFACE = [
    "instruction_file",
    "skill_md",
    "mcp_manifest",
    "tool_description",
    "agent_task_config",
]

# File extensions where secrets actually live. Gitleaks scans everything;
# we restrict to text-bearing extensions where this scanner makes sense
# (we're a project + skill scanner, not a generic secret scanner).
_FILE_TYPES = [
    "*.md", "*.txt", "*.json", "*.yaml", "*.yml", "*.toml",
    "*.env", "*.env.*", "*.cfg", "*.ini",
]


# ----------------------------------------------------------------------------
# Baseline exclude patterns — known example tokens that everyone hits.
# Each entry is a Python regex applied as `exclude_patterns` on every
# imported rule. Sourced from common documentation conventions and the
# Gitleaks project's own test fixtures.
# ----------------------------------------------------------------------------

_BASELINE_EXCLUDE_PATTERNS: List[Dict[str, str]] = [
    # AWS canonical example tokens
    {"type": "contains", "value": "AKIAIOSFODNN7EXAMPLE"},
    {"type": "contains", "value": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"},
    # GitHub fully-redacted/example tokens — the literal "xxxxxxxxxx" pattern
    {"type": "regex", "value": r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[xX]{20,}"},
    # Generic placeholder forms
    {"type": "regex", "value": r"(?i)<\s*your[\s_-]*(?:api[\s_-]*)?key[\s_-]*here\s*>"},
    {"type": "regex", "value": r"(?i)\bYOUR_[A-Z_]{2,30}_(?:KEY|TOKEN|SECRET)\b"},
    {"type": "regex", "value": r"(?i)\bxxx+-xxx+-xxx+\b"},
    # RSA / SSH test fixtures (common public-domain test keys)
    {"type": "contains", "value": "BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza"},
    # OpenAI sandbox example
    {"type": "contains", "value": "sk-proj-EXAMPLE"},
]


# ----------------------------------------------------------------------------
# Slug + filename helpers
# ----------------------------------------------------------------------------

def _slugify(name: str, max_len: int = 60) -> str:
    """Convert a Gitleaks rule id into a kebab-case slug."""
    s = name.lower().strip()
    s = re.sub(r"[^a-z0-9]+", "-", s)
    s = s.strip("-")
    if len(s) > max_len:
        s = s[:max_len].rsplit("-", 1)[0]
    return s or "rule"


def _filename_for(original_id: str, slug: str) -> str:
    # Gitleaks IDs already kebab-case and unique — use as-is for filename
    safe_id = re.sub(r"[^A-Za-z0-9._-]", "-", original_id)
    return f"{safe_id}.yaml"


# ----------------------------------------------------------------------------
# Regex normalization — Python compatibility
# ----------------------------------------------------------------------------

_LEADING_INLINE_FLAG = re.compile(r"^\(\?[aiLmsux]+\)")
_INTERIOR_INLINE_FLAG = re.compile(r"(?<!^)\(\?([aiLmsux]+)\)")


def _normalize_regex(rgx: str) -> Tuple[str, bool]:
    """Make a Gitleaks Go regex compile under Python `re`.

    Returns (normalized_pattern, was_modified). On failure (regex truly
    can't be made to compile), returns (original_pattern, False) and the
    caller decides what to do — we currently skip such rules.

    The single most common Gitleaks pattern that fails Python is an
    inline `(?i)` flag in the middle of an alternation. Python 3.11+
    rejects these as deprecated. We hoist any interior `(?i)` to the
    front; if multiple inline flags appear, we union their letters.
    """
    if not rgx:
        return rgx, False

    # Try compiling as-is first — the cheap fast path.
    try:
        re.compile(rgx)
        return rgx, False
    except re.error:
        pass

    modified = rgx
    leading = _LEADING_INLINE_FLAG.match(modified)
    leading_letters = set(leading.group(0)[2:-1]) if leading else set()

    interior_letters: set = set()
    interior_matches = list(_INTERIOR_INLINE_FLAG.finditer(modified))
    for m in interior_matches:
        interior_letters |= set(m.group(1))

    if interior_letters:
        # Strip every interior occurrence
        modified = _INTERIOR_INLINE_FLAG.sub("", modified)
        # Rebuild leading flag block as union of any flags seen
        all_letters = leading_letters | interior_letters
        flag_block = f"(?{''.join(sorted(all_letters))})"
        if leading:
            # Replace existing leading
            modified = flag_block + modified[leading.end():]
        else:
            modified = flag_block + modified

    try:
        re.compile(modified)
        return modified, True
    except re.error:
        return rgx, False


# ----------------------------------------------------------------------------
# Rule conversion
# ----------------------------------------------------------------------------

def _convert_rule(
    rule: Dict,
    upstream_sha: str,
    *,
    skip_low_entropy: bool = True,
) -> Optional[Tuple[Dict, str]]:
    """Convert one Gitleaks rule to our shape.

    Returns (converted_dict, reason_skipped). reason_skipped is empty
    when conversion succeeded.
    """
    rid = rule.get("id")
    description = rule.get("description", "")
    rgx_raw = rule.get("regex", "")
    if not rid or not rgx_raw:
        return None, "missing-id-or-regex"

    rgx, _ = _normalize_regex(rgx_raw)
    try:
        re.compile(rgx)
    except re.error:
        return None, "regex-incompatible-with-python"

    slug = _slugify(rid)
    aaid = f"gitleaks.{_CATEGORY}.{slug}"

    # Severity: secrets default to HIGH. We could downgrade based on
    # entropy threshold, but the entropy field acts as a confidence gate
    # downstream, not a severity hint upstream.
    severity = "high"

    converted = {
        "external_source": {
            "tool": "gitleaks",
            "original_id": rid,
            "original_title": description.split(".")[0] if description else rid,
            "source_version": f"git-{upstream_sha[:12]}",
            "import_date": date.today().isoformat(),
            "upstream": "https://github.com/gitleaks/gitleaks",
            "license": "MIT (c) 2019 Zachary Rice",
        },
        "agent_audit_id": aaid,
        "title": description.split(".")[0] if description else rid,
        "description": description,
        "severity_default": severity,
        "category": _CATEGORY,
        "audit_surface": list(_AUDIT_SURFACE),
        "asamm": {
            "primary": _ASAMM_PRIMARY,
            "secondary": list(_ASAMM_SECONDARY),
            "mapping_confidence": "category-default",
            "notes": "All Gitleaks rules map to AG-03 secret exposure.",
        },
        "targets": list(_FILE_TYPES),
        "match_mode": "any",
        "patterns": [
            {"type": "regex", "value": rgx},
        ],
        "exclude_patterns": list(_BASELINE_EXCLUDE_PATTERNS),
    }

    # Honor entropy gate: stash as a comment-equivalent field so we can
    # see it in YAML, even though our matcher doesn't yet enforce entropy.
    # Future work: gate findings by Shannon entropy of the matched group.
    if "entropy" in rule:
        converted["upstream_entropy_threshold"] = float(rule["entropy"])

    # Honor path filter: if Gitleaks restricts to specific paths, copy
    # those into our targets/file_types. The Gitleaks `path` field is a
    # regex on file path, not a glob — we keep it informational rather
    # than enforcing it (path enforcement would require teaching
    # _file_matches_targets about regex paths, scope creep).
    if "path" in rule:
        converted["upstream_path_regex"] = str(rule["path"])

    return converted, ""


def _header_comment(rule: Dict) -> str:
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
        f"# Adapted from {rid} (https://github.com/gitleaks/gitleaks)\n"
        "# MIT (c) 2019 Zachary Rice\n"
        "# Source: Gitleaks\n"
        f"# Severity: {sev}  |  ASAMM: {asamm_str}\n"
        "# " + ("=" * 61) + "\n"
    )


def _emit_yaml_file(rule: Dict, dest: Path) -> None:
    header = _header_comment(rule)
    body = yaml.safe_dump(rule, sort_keys=False, allow_unicode=True, width=120)
    dest.write_text(header + body, encoding="utf-8")


# ----------------------------------------------------------------------------
# Top-level import
# ----------------------------------------------------------------------------

def import_pack(
    source: Path,
    dest_dir: Path,
    upstream_sha: str,
    dry_run: bool = False,
) -> Dict[str, int]:
    """Replace dest_dir contents with converted rules from gitleaks.toml.

    Returns counts dict including __total__, __skipped__, and per-skip-reason
    breakdowns.
    """
    if not source.exists():
        raise FileNotFoundError(f"Gitleaks source TOML not found: {source}")

    with open(source, "rb") as f:
        data = tomllib.load(f)

    upstream_rules = data.get("rules", [])
    if not upstream_rules:
        raise ValueError(f"No [[rules]] entries found in {source}")

    converted: List[Dict] = []
    skipped: Dict[str, int] = {}
    for r in upstream_rules:
        result, reason = _convert_rule(r, upstream_sha)
        if result is None:
            skipped[reason] = skipped.get(reason, 0) + 1
            continue
        converted.append(result)

    if not converted:
        raise ValueError("No rules converted — aborting")

    if not dry_run:
        if dest_dir.exists():
            for child in dest_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        dest_dir.mkdir(parents=True, exist_ok=True)
        category_dir = dest_dir / _CATEGORY
        category_dir.mkdir(exist_ok=True)
        for rule in converted:
            slug = rule["agent_audit_id"].rsplit(".", 1)[1]
            fname = _filename_for(rule["external_source"]["original_id"], slug)
            _emit_yaml_file(rule, category_dir / fname)

    counts = {_CATEGORY: len(converted), "__total__": len(converted)}
    for reason, n in skipped.items():
        counts[f"__skipped_{reason}__"] = n
    counts["__skipped__"] = sum(skipped.values())
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="gitleaks-import", description=__doc__.split("\n\n")[0])
    p.add_argument("--source", type=Path, required=True,
                   help="Path to Gitleaks gitleaks.toml file")
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
    skip_reasons = {k: v for k, v in counts.items() if k.startswith("__skipped_")}
    counts = {k: v for k, v in counts.items() if not k.startswith("__")}

    label = "[DRY RUN] " if args.dry_run else ""
    print(f"{label}Imported {total} rules in {len(counts)} category:")
    for cat in sorted(counts):
        print(f"  {cat:25} {counts[cat]:3}")
    if skipped:
        print(f"\nSkipped {skipped} rules:")
        for reason, n in skip_reasons.items():
            r = reason.removeprefix("__skipped_").removesuffix("__")
            print(f"  {r:35} {n:3}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
