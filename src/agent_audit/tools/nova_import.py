# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""NOVA rule-pack importer — Roadmap items A2/C1.

NOVA (https://github.com/Nova-Hunting/nova-rules) is a YARA-inspired
prompt-pattern matching DSL for LLM threat detection. Each rule has up
to three sections:

  - keywords:  string literals or regex patterns
  - semantics: natural-language patterns with similarity threshold
  - llm:       natural-language evaluation questions with confidence threshold

NOVA's full evaluator requires an embedding model (semantics) and an LLM
endpoint (llm). We import only the **keywords** section into our rule
pack — the semantics and llm sections are preserved as informational
metadata for future enforcement when those evaluators land.

## Conversion strategy (keywords-only, lossy by design)

For each NOVA rule:
  1. Parse the keyword block. String literals become `contains` excludes
     turned into anchor-free regexes. `/.../` regex literals are passed
     through (with a Python-RE2 normalization pass).
  2. Read the `condition:` line and decide match_mode:
       - "any of keywords.*"          → match_mode: any
       - "2 of keywords.*"            → match_mode: any (with note;
                                          our matcher doesn't support 2-of yet)
       - "keywords.*"                 → match_mode: any (treated as any-of)
       - explicit single keyword      → match_mode: any
       - mixes with semantics/llm     → match_mode: any
                                          (only keyword side is enforced)
  3. Skip rules whose condition has zero keyword references — those are
     pure semantics/llm rules and have nothing for the regex engine to do.
  4. Severity from meta block (default: medium); category is derived
     from `category = "..."` meta value, mapped to our internal categories.
  5. ASAMM and OWASP mappings come from the category mapping table below.

## What is NOT imported

- `semantics:` patterns (preserved in upstream_semantics_patterns
  metadata field for future enforcement)
- `llm:` evaluation prompts (preserved in upstream_llm_checks)
- `condition:` boolean structure beyond simple any-of (logged as
  upstream_condition_raw for review)

When the M3 NOVA evaluator lands (out of scope for v0.17), it can
consume the metadata fields directly to enforce the full rule.
"""
from __future__ import annotations

import argparse
import re
import shutil
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import yaml


_DEFAULT_DEST = (
    Path(__file__).resolve().parent.parent
    / "knowledge" / "rule_packs" / "external" / "nova"
)


# ----------------------------------------------------------------------------
# Category mapping — NOVA uses path-style categories like
# "prompt_manipulation/jailbreak". Map each NOVA top-level category to
# one of our existing internal categories so MCP/ASI mapping flows.
# ----------------------------------------------------------------------------

_NOVA_CATEGORY_MAP: Dict[str, str] = {
    "prompt_manipulation": "prompt-injection",
    "suspicious_patterns": "prompt-injection",
    "abnormal_outputs": "context-exfiltration",
    "code_execution": "command-execution",
    "incidents": "third-party-content",
    # Default catch-all when category meta is missing or unknown:
    "_default": "prompt-injection",
}

# ASAMM defaults per resolved internal category. Most NOVA rules deal
# with prompt-injection / hidden-instruction patterns → AI-04, AI-05.
_INTERNAL_CATEGORY_META: Dict[str, Dict] = {
    "prompt-injection": {
        "asamm_primary": "AI-04",
        "asamm_secondary": ["AI-05"],
        # Static surfaces only. NOVA rules without their semantics/llm
        # evaluator gates fire on benign user input — too noisy for
        # forensic mode. Lift this restriction in M3.
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "context-exfiltration": {
        "asamm_primary": "AI-03",
        "asamm_secondary": ["AG-03"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "command-execution": {
        "asamm_primary": "AD-02",
        "asamm_secondary": ["AG-02", "AD-04"],
        "audit_surface": ["instruction_file", "skill_md", "tool_description"],
    },
    "third-party-content": {
        "asamm_primary": "AI-03",
        "asamm_secondary": ["AG-02"],
        "audit_surface": ["instruction_file", "skill_md"],
    },
}


# ----------------------------------------------------------------------------
# .nov parser — minimal hand-rolled, no full DSL grammar
# ----------------------------------------------------------------------------

@dataclass
class NovaRule:
    name: str
    meta: Dict[str, str] = field(default_factory=dict)
    keywords: List[Tuple[str, str, str]] = field(default_factory=list)
    # (varname, kind, value) where kind ∈ {"string", "regex"}
    semantics: List[Tuple[str, str, Optional[float]]] = field(default_factory=list)
    # (varname, prose, threshold)
    llm: List[Tuple[str, str, Optional[float]]] = field(default_factory=list)
    condition: str = ""
    source_file: Optional[Path] = None


_RULE_HEADER = re.compile(r"\brule\s+(\w+)\s*\{")
_META_LINE = re.compile(r'^\s*(\w+)\s*=\s*"([^"]*)"')
_KW_LITERAL = re.compile(r'^\s*\$(\w+)\s*=\s*"([^"]*)"')
_KW_REGEX = re.compile(r'^\s*\$(\w+)\s*=\s*/(.*)/([gimsux]*)\s*$')
_SEM_LINE = re.compile(r'^\s*\$(\w+)\s*=\s*"([^"]*)"\s*(?:\(([\d.]+)\))?')
_LLM_LINE = re.compile(r'^\s*\$(\w+)\s*=\s*"([^"]*)"\s*(?:\(([\d.]+)\))?')


def _split_rules(text: str) -> List[str]:
    """Yield individual rule bodies (the `rule X { ... }` blocks)."""
    out = []
    i = 0
    while True:
        m = _RULE_HEADER.search(text, i)
        if not m:
            break
        # Find matching close brace by counting depth
        depth = 1
        j = m.end()
        while j < len(text) and depth:
            ch = text[j]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            j += 1
        out.append(text[m.start():j])
        i = j
    return out


def _parse_section(body: str, name: str) -> List[str]:
    """Return raw lines under section `name:` until the next section header
    or the closing `}` of the rule. Names: meta, keywords, semantics, llm,
    condition."""
    pat = re.compile(rf"\n\s*{re.escape(name)}\s*:\s*\n((?:.|\n)*?)(?=\n\s*(?:meta|keywords|semantics|llm|condition)\s*:|\n\s*\}}\s*$)")
    m = pat.search(body)
    if not m:
        return []
    return [ln for ln in m.group(1).splitlines() if ln.strip()]


def parse_nov_file(path: Path) -> List[NovaRule]:
    text = path.read_text(encoding="utf-8")
    out: List[NovaRule] = []
    for body in _split_rules(text):
        m = _RULE_HEADER.search(body)
        if not m:
            continue
        rule = NovaRule(name=m.group(1), source_file=path)

        # meta
        for line in _parse_section(body, "meta"):
            mm = _META_LINE.match(line)
            if mm:
                rule.meta[mm.group(1)] = mm.group(2)

        # keywords
        for line in _parse_section(body, "keywords"):
            kr = _KW_REGEX.match(line)
            if kr:
                rule.keywords.append((kr.group(1), "regex", kr.group(2)))
                continue
            kl = _KW_LITERAL.match(line)
            if kl:
                rule.keywords.append((kl.group(1), "string", kl.group(2)))
                continue

        # semantics
        for line in _parse_section(body, "semantics"):
            sm = _SEM_LINE.match(line)
            if sm:
                threshold = float(sm.group(3)) if sm.group(3) else None
                rule.semantics.append((sm.group(1), sm.group(2), threshold))

        # llm
        for line in _parse_section(body, "llm"):
            lm = _LLM_LINE.match(line)
            if lm:
                threshold = float(lm.group(3)) if lm.group(3) else None
                rule.llm.append((lm.group(1), lm.group(2), threshold))

        # condition — single line(s), trimmed
        cond_lines = _parse_section(body, "condition")
        rule.condition = " ".join(ln.strip() for ln in cond_lines)

        out.append(rule)
    return out


# ----------------------------------------------------------------------------
# Slug + helpers
# ----------------------------------------------------------------------------

def _slugify(name: str, max_len: int = 60) -> str:
    """CamelCase rule name → kebab-case slug."""
    # Insert hyphen before each uppercase that follows lowercase
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", name)
    s = s.lower()
    s = re.sub(r"[^a-z0-9]+", "-", s).strip("-")
    if len(s) > max_len:
        s = s[:max_len].rsplit("-", 1)[0]
    return s or "rule"


def _normalize_severity(s: str) -> str:
    s = (s or "medium").strip().lower()
    return s if s in ("low", "medium", "high", "critical") else "medium"


def _resolve_internal_category(nova_category: str) -> str:
    """Resolve NOVA's path-style category to one of our internal ones."""
    if not nova_category:
        return _NOVA_CATEGORY_MAP["_default"]
    top = nova_category.split("/", 1)[0].strip().lower()
    return _NOVA_CATEGORY_MAP.get(top, _NOVA_CATEGORY_MAP["_default"])


def _condition_to_match_mode(condition: str, n_keywords: int) -> Tuple[str, str]:
    """Decide match_mode based on the condition expression.

    Returns (match_mode, note). `note` documents the mapping for the
    YAML so reviewers can see why we chose what we did.
    """
    cond = re.sub(r"\s+", " ", condition or "").strip().lower()
    if not cond:
        return "any", "no condition declared, default any-of"
    # Pure any-of forms
    if cond in {"any of keywords.*", "keywords.*"}:
        return "any", "any-of keywords"
    # 'N of' literal — Python matcher doesn't support N-of; we conservatively
    # require 'all of' so the rule fires only on strong matches.
    m = re.match(r"^(\d+)\s+of\s+keywords\.\*$", cond)
    if m:
        n = int(m.group(1))
        if n >= n_keywords:
            return "all", f"upstream '{n} of', requires all keywords (n={n_keywords})"
        # Closest safe approximation: any-of, with a note. We'd otherwise
        # need a custom 'k-of-n' match mode in the loader.
        return "any", f"upstream '{n} of {n_keywords}', approximated as any-of"
    # Mixed conditions involving semantics/llm: only the keyword side is
    # enforced. If the condition uses 'and (any of llm.*)', dropping the
    # llm side relaxes to 'any of keywords.*'.
    if "any of keywords.*" in cond:
        return "any", "mixed condition; keyword side approximated as any-of"
    # Single explicit keyword reference like 'keywords.$xyz' — match_mode
    # any will fire on that pattern alone, which is what upstream means.
    if re.search(r"keywords\.\$\w+", cond):
        return "any", "explicit keyword refs only, any-of"
    # Conditions with 'all of keywords.*'
    if cond.startswith("all of keywords"):
        return "all", "all-of keywords"
    # Fallback: any-of with explicit note so reviewer knows we punted.
    return "any", f"unrecognized condition shape: {condition!r}; defaulted to any-of"


# ----------------------------------------------------------------------------
# Conversion
# ----------------------------------------------------------------------------

def convert_rule(rule: NovaRule, upstream_sha: str) -> Optional[Tuple[Dict, str]]:
    """Convert a NovaRule to our YAML shape. Returns (dict, reason) where
    reason is empty on success."""
    if not rule.keywords:
        # NOVA rules with only semantics/llm have nothing for our regex
        # engine to enforce. Skip — not a failure, just out of scope.
        return None, "no-keywords-section"

    nova_category = rule.meta.get("category", "")
    internal_cat = _resolve_internal_category(nova_category)
    cat_meta = _INTERNAL_CATEGORY_META.get(internal_cat) or _INTERNAL_CATEGORY_META["prompt-injection"]

    upstream_severity_raw = _normalize_severity(rule.meta.get("severity", ""))

    # NOVA rules are designed to fire only when keywords + semantics + llm
    # all line up under their condition expression. We import keywords only;
    # the semantics/llm gates are dropped. Without those gates, keyword-only
    # matches fire on benign content (calibration showed rules matching
    # generic words like "code", "script", "image", or any two-word capitalized
    # name pattern). All NOVA rules ship at LOW severity until M3 (NOVA
    # evaluator) lands. Per-rule overrides in rule_pack_overrides.yaml can
    # restore higher severity for narrow patterns once we audit them.
    severity = "low"
    severity_demotion_note = (
        "Severity floored at LOW on import: NOVA semantics/llm gates are "
        "not enforced by the current matcher, so keyword-only signal is "
        "weaker than upstream intended. Calibration on benign skills "
        "showed multi-word keyword conjunctions firing on innocuous "
        "documentation. Lift selectively when M3 NOVA evaluator lands."
    )
    slug = _slugify(rule.name)
    aaid = f"nova.{internal_cat}.{slug}"

    # Compile keyword patterns into our shape
    patterns = []
    for varname, kind, value in rule.keywords:
        if kind == "regex":
            # Pass through; rule_pack_loader's compile step does its own
            # warnings suppression and Python-compat checks.
            patterns.append({"type": "regex", "value": value})
        else:
            # String literal — turn into a case-insensitive escaped regex
            # since NOVA semantically treats keywords as substring matches.
            patterns.append({"type": "regex", "value": "(?i)" + re.escape(value)})

    if not patterns:
        return None, "all-keywords-failed-to-compile"

    match_mode, condition_note = _condition_to_match_mode(rule.condition, len(rule.keywords))

    converted = {
        "external_source": {
            "tool": "nova",
            "original_id": rule.name,
            "original_title": rule.name,
            "source_version": f"git-{upstream_sha[:12]}",
            "import_date": date.today().isoformat(),
            "upstream": "https://github.com/Nova-Hunting/nova-rules",
            "license": "MIT (c) 2025 Thomas Roccia",
        },
        "agent_audit_id": aaid,
        "title": rule.meta.get("description", rule.name),
        "description": rule.meta.get("description", ""),
        "severity_default": severity,
        "category": internal_cat,
        "audit_surface": list(cat_meta["audit_surface"]),
        "asamm": {
            "primary": cat_meta["asamm_primary"],
            "secondary": list(cat_meta["asamm_secondary"]),
            "mapping_confidence": "category-default",
            "notes": "Derived from NOVA category mapping at import.",
        },
        "match_mode": match_mode,
        "patterns": patterns,
        "exclude_patterns": [],
        # Original upstream severity is preserved as a structured field so
        # the M3 NOVA evaluator can lift the floored severity back up when
        # both gates pass. This is read by rule_pack_loader and exposed as
        # RulePackRule.upstream_severity.
        "upstream_severity": upstream_severity_raw,
    }

    # Preserve upstream metadata for future evaluator
    if rule.semantics:
        converted["upstream_semantics_patterns"] = [
            {"name": v, "prose": p, "threshold": t}
            for v, p, t in rule.semantics
        ]
    if rule.llm:
        converted["upstream_llm_checks"] = [
            {"name": v, "prompt": p, "threshold": t}
            for v, p, t in rule.llm
        ]
    if rule.condition:
        converted["upstream_condition_raw"] = rule.condition
    converted["upstream_condition_mapping_note"] = condition_note
    converted["upstream_severity_demotion_note"] = severity_demotion_note

    if "uuid" in rule.meta:
        converted["external_source"]["upstream_uuid"] = rule.meta["uuid"]
    if "author" in rule.meta:
        converted["external_source"]["upstream_author"] = rule.meta["author"]

    return converted, ""


def _header_comment(rule_dict: Dict) -> str:
    aaid = rule_dict["agent_audit_id"]
    src = rule_dict["external_source"]
    rid = src["original_id"]
    sev = rule_dict["severity_default"]
    asamm = rule_dict["asamm"]
    asamm_str = asamm["primary"]
    if asamm["secondary"]:
        asamm_str += f" (+{','.join(asamm['secondary'])})"
    return (
        "# " + ("=" * 61) + "\n"
        f"# {aaid}\n"
        "# " + ("=" * 61) + "\n"
        f"# Adapted from {rid} (https://github.com/Nova-Hunting/nova-rules)\n"
        "# MIT (c) 2025 Thomas Roccia\n"
        "# Source: NOVA\n"
        f"# Severity: {sev}  |  ASAMM: {asamm_str}\n"
        "# Note: NOVA's semantics/llm sections are preserved as metadata\n"
        "# but not enforced by the current matcher (regex-only).\n"
        "# " + ("=" * 61) + "\n"
    )


def _emit_yaml_file(rule_dict: Dict, dest: Path) -> None:
    header = _header_comment(rule_dict)
    body = yaml.safe_dump(rule_dict, sort_keys=False, allow_unicode=True, width=120)
    dest.write_text(header + body, encoding="utf-8")


# ----------------------------------------------------------------------------
# Top-level import
# ----------------------------------------------------------------------------

def import_pack(
    source_dir: Path,
    dest_dir: Path,
    upstream_sha: str,
    dry_run: bool = False,
) -> Dict[str, int]:
    """Walk source_dir for *.nov files, parse, convert, emit."""
    if not source_dir.exists():
        raise FileNotFoundError(f"NOVA source dir not found: {source_dir}")

    nov_files = sorted(source_dir.rglob("*.nov"))
    if not nov_files:
        raise ValueError(f"No .nov files found under {source_dir}")

    by_internal_category: Dict[str, List[Dict]] = {}
    skipped: Dict[str, int] = {}
    for nov in nov_files:
        try:
            rules = parse_nov_file(nov)
        except Exception as e:
            print(f"WARNING: failed to parse {nov.name}: {e}", file=sys.stderr)
            skipped["parse-error"] = skipped.get("parse-error", 0) + 1
            continue
        for r in rules:
            converted, reason = convert_rule(r, upstream_sha)
            if converted is None:
                skipped[reason] = skipped.get(reason, 0) + 1
                continue
            cat = converted["category"]
            by_internal_category.setdefault(cat, []).append(converted)

    if not by_internal_category:
        raise ValueError("No NOVA rules converted — aborting")

    if not dry_run:
        if dest_dir.exists():
            for child in dest_dir.iterdir():
                if child.is_dir():
                    shutil.rmtree(child)
                else:
                    child.unlink()
        dest_dir.mkdir(parents=True, exist_ok=True)
        for cat, rules in sorted(by_internal_category.items()):
            cat_dir = dest_dir / cat
            cat_dir.mkdir(exist_ok=True)
            for rule_dict in rules:
                slug = rule_dict["agent_audit_id"].rsplit(".", 1)[1]
                fname = f"{rule_dict['external_source']['original_id']}-{slug}.yaml"
                # Sanitize for filesystem
                fname = re.sub(r"[^A-Za-z0-9._-]", "-", fname)
                _emit_yaml_file(rule_dict, cat_dir / fname)

    counts = {cat: len(rs) for cat, rs in by_internal_category.items()}
    counts["__total__"] = sum(counts.values())
    counts["__skipped__"] = sum(skipped.values())
    for r, n in skipped.items():
        counts[f"__skipped_{r}__"] = n
    return counts


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="nova-import", description=__doc__.split("\n\n")[0])
    p.add_argument("--source", type=Path, required=True,
                   help="Path to upstream nova-rules checkout (root or subdir)")
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
    print(f"{label}Imported {total} rules across {len(counts)} categories:")
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
