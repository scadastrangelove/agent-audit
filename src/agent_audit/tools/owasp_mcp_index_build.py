# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Generate the machine-readable OWASP MCP Top 10 index from upstream markdown.

Run as part of the vendored-data refresh workflow. Reads the per-category
markdown files (MCP01-2025-*.md … MCP10-2025-*.md) and writes a single
owasp_mcp_top10.yaml index next to them.

Why a separate generated file: the markdowns are CC BY-SA 4.0 prose, useful
for humans. The validator and finding_dedup mapping want a tiny structured
file with stable IDs and titles. We keep both.

Usage:
    python -m agent_audit.tools.owasp_mcp_index_build
    # produces src/agent_audit/data/owasp_mcp/owasp_mcp_top10.yaml

The output file is committed to the repo, so this script runs only at
refresh time, not at every install.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Dict, List, Optional

import yaml


_DEFAULT_DIR = Path(__file__).resolve().parent.parent / "data" / "owasp_mcp"
_DEFAULT_OUTPUT = _DEFAULT_DIR / "owasp_mcp_top10.yaml"

# Source title format: 'MCP01:2025 - Token Mismanagement and Secret Exposure'
# Note: upstream uses both '-' (hyphen) and '–' (en-dash) inconsistently as separator.
_TITLE_RE = re.compile(r'title:\s*"((MCP\d+):2025[^"]+)"')
_TITLE_SPLIT_RE = re.compile(r'\s+[-–]\s+', re.UNICODE)
# Description heading is '### Description' or '### Description:' inconsistently.
# We capture everything up to the next '### ' heading.
_DESC_RE = re.compile(r'###\s*Description:?\s*\n+(.+?)(?=\n+###\s)', re.S)


def parse_markdown(path: Path) -> Optional[Dict[str, str]]:
    """Return {id, title, description} for one MCP markdown file, or None."""
    text = path.read_text(encoding="utf-8")
    m_title = _TITLE_RE.search(text)
    if not m_title:
        return None
    full_title = m_title.group(1)
    mcp_id = m_title.group(2)
    parts = _TITLE_SPLIT_RE.split(full_title, maxsplit=1)
    short_name = parts[1].strip() if len(parts) > 1 else full_title.strip()

    desc = ""
    m_desc = _DESC_RE.search(text)
    if m_desc:
        # Collapse whitespace for stable serialization. Keep paragraphs delimited
        # by single spaces — we don't reproduce upstream prose verbatim, just a
        # short canonical reference description.
        raw = m_desc.group(1).strip()
        # Take first 1-2 paragraphs (separated by blank line) at most
        first_block = raw.split("\n\n", 2)[0]
        desc = re.sub(r"\s+", " ", first_block).strip()

    return {"id": mcp_id, "title": short_name, "description": desc}


def build_index(source_dir: Path) -> Dict:
    """Produce the OWASP MCP Top 10 index dict from a directory of markdowns."""
    md_files = sorted(source_dir.glob("MCP*.md"))
    entries: List[Dict[str, str]] = []
    for md in md_files:
        parsed = parse_markdown(md)
        if parsed:
            entries.append(parsed)
    entries.sort(key=lambda e: e["id"])
    return {
        "name": "OWASP MCP Top 10",
        "year": 2025,
        "version": "v0.1-beta-2025",
        "license": "CC BY-SA 4.0",
        "source": "https://github.com/OWASP/www-project-mcp-top-10",
        "categories": entries,
    }


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="owasp-mcp-index-build", description=__doc__.split("\n\n")[0])
    p.add_argument("--source", type=Path, default=_DEFAULT_DIR,
                   help=f"Directory containing the upstream markdowns (default: {_DEFAULT_DIR})")
    p.add_argument("--output", type=Path, default=_DEFAULT_OUTPUT,
                   help=f"Output YAML path (default: {_DEFAULT_OUTPUT})")
    args = p.parse_args(argv)

    if not args.source.exists():
        print(f"ERROR: source directory not found: {args.source}", file=sys.stderr)
        return 2

    index = build_index(args.source)
    if len(index["categories"]) != 10:
        print(
            f"WARNING: expected exactly 10 categories, got {len(index['categories'])}. "
            f"Source markdowns may be incomplete.",
            file=sys.stderr,
        )

    args.output.write_text(
        yaml.safe_dump(index, sort_keys=False, allow_unicode=True, width=200),
        encoding="utf-8",
    )
    print(f"Wrote {args.output} with {len(index['categories'])} categories.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
