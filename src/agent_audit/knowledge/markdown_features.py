"""Markdown AST feature extractor — v0.12 AST Precision step D-1.

See docs/ast-precision-plan.md for context. This module is the first
concrete step in the AST Precision track: parse markdown once, derive
a small set of features that native detectors consume instead of raw
text. Does NOT build a product-wide IR.

Features:
  - text_without_code: prose with code fences removed
  - code_blocks_by_lang: dict language -> list of fence contents
  - heading_paths: list of heading breadcrumbs (e.g., "## Safety > ### Rules")

Detectors decide which feature they need. Rule packs are unaffected —
they still operate on raw text.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List

try:
    from markdown_it import MarkdownIt
except ImportError:  # pragma: no cover
    MarkdownIt = None  # type: ignore


@dataclass
class MarkdownFeatures:
    """Parsed view of a markdown file."""
    text_without_code: str
    code_blocks_by_lang: Dict[str, List[str]]
    heading_paths: List[str]
    # The original text, for fallback
    raw: str
    # Did AST parsing actually succeed?
    ast_available: bool = True


# Single shared parser — commonmark + GFM tables.
# Tables matter: skill specs commonly use tables to enumerate capabilities
# ("| Ask Claude to... | What happens |"), and that content must reach
# detectors as prose, not be dropped.
_MD_PARSER = (
    MarkdownIt("commonmark").enable("table")
    if MarkdownIt is not None else None
)


def extract(text: str) -> MarkdownFeatures:
    """Extract features from markdown text.

    Returns MarkdownFeatures. If markdown-it-py is unavailable or parsing
    fails, returns a fallback where `text_without_code == raw` and no
    code blocks are separated. Detectors must handle this degraded mode
    by falling back to current raw-text behavior.
    """
    if _MD_PARSER is None:
        return MarkdownFeatures(
            text_without_code=text,
            code_blocks_by_lang={},
            heading_paths=[],
            raw=text,
            ast_available=False,
        )

    try:
        tokens = _MD_PARSER.parse(text)
    except Exception:
        return MarkdownFeatures(
            text_without_code=text,
            code_blocks_by_lang={},
            heading_paths=[],
            raw=text,
            ast_available=False,
        )

    prose_parts: List[str] = []
    code_by_lang: Dict[str, List[str]] = {}
    heading_stack: List[tuple[int, str]] = []  # (level, title)
    heading_paths: List[str] = []

    # Track heading context to join with collected text
    pending_heading_title: str = ""
    pending_heading_level: int = 0

    for tok in tokens:
        t = tok.type
        if t == "fence":
            # tok.info = language hint ("bash", "python", or "")
            info = (tok.info or "").strip()
            lang = info.split()[0].lower() if info else "plain"
            code_by_lang.setdefault(lang, []).append(tok.content)
            continue
        if t == "code_block":
            # Indented code block (no language hint)
            code_by_lang.setdefault("plain", []).append(tok.content)
            continue
        if t == "heading_open":
            pending_heading_level = int(tok.tag[1:])  # "h2" -> 2
            pending_heading_title = ""
            continue
        if t == "heading_close":
            # Pop stack to current level-1, then push this heading
            while heading_stack and heading_stack[-1][0] >= pending_heading_level:
                heading_stack.pop()
            heading_stack.append((pending_heading_level, pending_heading_title.strip()))
            path = " > ".join(f"{'#' * lvl} {title}" for lvl, title in heading_stack)
            heading_paths.append(path)
            # Heading text IS prose — include it
            prose_parts.append(pending_heading_title.strip())
            pending_heading_title = ""
            pending_heading_level = 0  # reset — subsequent inlines are paragraphs
            continue
        if t == "inline":
            # Inline children = text content of enclosing block
            if pending_heading_level > 0 and not pending_heading_title:
                # This inline belongs to the heading being opened
                pending_heading_title = tok.content
            else:
                prose_parts.append(tok.content)
            continue
        # Other token types (paragraph_open/close, list markers, hr, etc.)
        # carry no text we need

    text_without_code = "\n\n".join(p for p in prose_parts if p.strip())

    return MarkdownFeatures(
        text_without_code=text_without_code,
        code_blocks_by_lang=code_by_lang,
        heading_paths=heading_paths,
        raw=text,
        ast_available=True,
    )
