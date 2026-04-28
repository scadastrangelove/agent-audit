"""Lexicon audit tool — count per-pattern matches across a corpus.

Usage:
    python -m agent_audit.tools.lexicon_audit PATH_TO_CORPUS [--top N]

For each pattern in capability_lexicon.py, counts:
    - how many distinct files matched (recall-ish metric)
    - how many total matches (fired once per file × N)
    - ratio = total / distinct_files (high ratio = match-dense files)

Writes a Markdown report to stdout. Combined with a manual review of
the top N match samples, the report tells you which patterns are the
next FP candidates and which are actually signal-dense.

This is a standalone audit tool — it does NOT produce findings, just
pattern-match telemetry. Safe to run on arbitrarily large corpora.
"""
from __future__ import annotations

import argparse
from collections import defaultdict
from pathlib import Path
from typing import List

from ..knowledge.capability_lexicon import (
    APPROVAL_MARKER,
    AUTONOMY_LOOP,
    EXTERNAL_REPLY,
    MANIFEST_NATIVE_MAPPING,
    REMOTE_ACTION_SURFACE,
    SESSION_REUSE,
    WRITE_ACTION,
)
from ..knowledge.identity_lexicon import (
    IDENTITY_HARD,
    IDENTITY_SOFT,
    PERSIST_WRITE,
    TEMPLATE_CONTEXT,
)
from ..knowledge.markdown_features import extract

LEXICONS = [
    ("REMOTE_ACTION_SURFACE", REMOTE_ACTION_SURFACE),
    ("SESSION_REUSE", SESSION_REUSE),
    ("AUTONOMY_LOOP", AUTONOMY_LOOP),
    ("WRITE_ACTION", WRITE_ACTION),
    ("EXTERNAL_REPLY", EXTERNAL_REPLY),
    ("MANIFEST_NATIVE_MAPPING", MANIFEST_NATIVE_MAPPING),
    ("APPROVAL_MARKER", APPROVAL_MARKER),
    ("IDENTITY_HARD", IDENTITY_HARD),
    ("IDENTITY_SOFT", IDENTITY_SOFT),
    ("PERSIST_WRITE", PERSIST_WRITE),
    ("TEMPLATE_CONTEXT", TEMPLATE_CONTEXT),
]

_TARGET_NAMES = {"SKILL.md", "AGENTS.md", "CLAUDE.md", "GEMINI.md"}


def _walk_instruction_files(root: Path):
    """Yield all SKILL.md / AGENTS.md / CLAUDE.md files under root."""
    for p in root.rglob("*"):
        if not p.is_file():
            continue
        if p.name in _TARGET_NAMES:
            yield p


def audit_corpus(root: Path, use_prose_only: bool = True):
    """Run lexicon audit over a corpus.

    Returns dict keyed by (lexicon_name, pattern_str):
        {files, matches, examples[up to 3]}
    """
    stats = defaultdict(lambda: {"files": 0, "matches": 0, "examples": []})
    total_files = 0

    for p in _walk_instruction_files(root):
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if use_prose_only:
            features = extract(text)
            scan_text = features.text_without_code if features.ast_available else text
        else:
            scan_text = text
        total_files += 1

        # For each lexicon/pattern, record matches in this file
        for lex_name, patterns in LEXICONS:
            for pat in patterns:
                matches = list(pat.finditer(scan_text))
                if not matches:
                    continue
                key = (lex_name, pat.pattern)
                stats[key]["files"] += 1
                stats[key]["matches"] += len(matches)
                if len(stats[key]["examples"]) < 3:
                    # Save one sample match with surrounding context
                    m = matches[0]
                    start = max(0, m.start() - 40)
                    end = min(len(scan_text), m.end() + 40)
                    snippet = scan_text[start:end].replace("\n", " ")
                    stats[key]["examples"].append({
                        "file": str(p),
                        "match": m.group(),
                        "context": snippet,
                    })

    return stats, total_files


def render_report(stats, total_files: int, top_n: int = 30) -> str:
    """Produce Markdown report — top N patterns by match-count, with context."""
    lines = [
        "# Lexicon audit report",
        "",
        f"Scanned: {total_files} instruction files",
        "",
        "Metrics per pattern:",
        "- `files`: distinct files that fired at least once",
        "- `matches`: total match occurrences (can exceed `files`)",
        "- `density`: matches / files — high values mean match-dense files",
        "",
    ]

    # Group by lexicon
    by_lex = defaultdict(list)
    for (lex, pat), s in stats.items():
        by_lex[lex].append((pat, s))

    for lex in [
        "REMOTE_ACTION_SURFACE", "WRITE_ACTION", "AUTONOMY_LOOP",
        "EXTERNAL_REPLY", "APPROVAL_MARKER", "SESSION_REUSE",
        "IDENTITY_HARD", "IDENTITY_SOFT", "PERSIST_WRITE",
        "MANIFEST_NATIVE_MAPPING", "TEMPLATE_CONTEXT",
    ]:
        items = by_lex.get(lex, [])
        if not items:
            continue
        lines.append(f"## {lex}")
        lines.append("")
        items.sort(key=lambda x: -x[1]["matches"])
        lines.append("| Pattern | files | matches | density | example match |")
        lines.append("|---|---:|---:|---:|---|")
        for pat, s in items:
            density = s["matches"] / max(1, s["files"])
            ex = s["examples"][0] if s["examples"] else {}
            example_match = ex.get("match", "")
            pat_short = pat[:60] + ("..." if len(pat) > 60 else "")
            lines.append(
                f"| `{pat_short}` | {s['files']} | {s['matches']} | "
                f"{density:.1f} | `{example_match}` |"
            )
        lines.append("")

    # Top density (potential FP candidates — low files, high density)
    lines.append("## Top-density patterns (FP candidates)")
    lines.append("")
    lines.append(
        "Patterns with high match-per-file density are suspicious: either "
        "signal-dense TPs or match-heavy FPs. Manual review needed."
    )
    lines.append("")
    all_patterns = [
        (lex, pat, s) for (lex, pat), s in stats.items()
        if s["files"] > 0
    ]
    all_patterns.sort(key=lambda x: -(x[2]["matches"] / max(1, x[2]["files"])))
    lines.append("| Lexicon | Pattern | files | matches | density |")
    lines.append("|---|---|---:|---:|---:|")
    for lex, pat, s in all_patterns[:top_n]:
        density = s["matches"] / max(1, s["files"])
        pat_short = pat[:50] + ("..." if len(pat) > 50 else "")
        lines.append(f"| {lex} | `{pat_short}` | {s['files']} | {s['matches']} | {density:.1f} |")
    lines.append("")

    # Example contexts for the top 10 densest patterns
    lines.append("## Example contexts (top 10 densest)")
    lines.append("")
    for lex, pat, s in all_patterns[:10]:
        pat_short = pat[:60]
        lines.append(f"### {lex} — `{pat_short}`")
        lines.append("")
        for ex in s["examples"][:3]:
            f_short = "/".join(str(ex["file"]).split("/")[-3:])
            lines.append(f"- **{f_short}** — `{ex['match']}`")
            lines.append(f"  - context: `{ex['context']}`")
        lines.append("")

    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Lexicon audit over a corpus")
    ap.add_argument("path", type=Path, help="Root dir to scan recursively")
    ap.add_argument("--top", type=int, default=30, help="Top-N density patterns")
    ap.add_argument("--use-raw", action="store_true",
                    help="Scan raw text, not prose-only (default: prose-only)")
    ap.add_argument("--output", "-o", type=Path, default=None,
                    help="Write Markdown report to file (default: stdout)")
    args = ap.parse_args(argv)

    stats, total = audit_corpus(args.path, use_prose_only=not args.use_raw)
    report = render_report(stats, total, top_n=args.top)
    if args.output:
        args.output.write_text(report)
        print(f"Wrote {args.output}")
    else:
        print(report)


if __name__ == "__main__":
    main()
