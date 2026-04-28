"""Text filters — identify non-content regions in assistant text.

Used by claim_detector to skip quoted content, code blocks, and log
output before scoring. Without these filters, a claim-looking sentence
inside a code example or a quoted error message triggers false
positives.

All functions are pure, operate on strings, zero dependencies.
"""
from __future__ import annotations

import re
from typing import List, Tuple


# --- Code block detection ---

# Fenced code blocks (```...``` or ~~~...~~~).
# Match content between opening and closing fence, lazy so multiple blocks work.
_FENCED_CODE = re.compile(r"```[\s\S]*?```|~~~[\s\S]*?~~~", re.MULTILINE)

# Inline code spans — single/double backticks.
_INLINE_CODE = re.compile(r"`[^`\n]+`")


# --- Quote detection ---

# Markdown blockquote (line starts with `>`)
_QUOTE_LINE = re.compile(r"^\s*>\s?", re.MULTILINE)

# Reporting verbs — sentences starting with someone else's utterance
_REPORTING_PREFIX = re.compile(
    r"""
    ^[\s]*
    (?:
        (?:he|she|they|it|the\s+user|the\s+tool|the\s+log)
        \s+
        (?:said|mentioned|reported|replied|responded|noted|wrote|stated|claimed|asked|suggested)
    )
    \b
    """,
    re.IGNORECASE | re.VERBOSE,
)


# --- Log-like line detection ---

# Timestamps in common formats
_TIMESTAMP_LINE = re.compile(
    r"""
    (?:^|\s)
    (?:
        # ISO 8601
        \d{4}-\d{2}-\d{2}[\sT]\d{2}:\d{2}:\d{2}
        # syslog / rsyslog
      | \w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}
        # git log / docker
      | \d{10,}                              # unix timestamp
    )
    """,
    re.VERBOSE,
)

# Log levels as first token — definite log output
_LOG_LEVEL_PREFIX = re.compile(
    r"""
    ^[\s\[\(]*
    (?:DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL|TRACE|NOTICE)
    [\s\]\):]
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Stack trace line — "at <method> (<file>:<line>)" or Python traceback
_STACK_TRACE_LINE = re.compile(
    r"""
    (?:
        ^\s*at\s+\S+\s*\(\S+:\d+\)           # Java/JS
      | ^\s*File\s+"[^"]+",\s*line\s+\d+      # Python
      | ^\s+Traceback\s+\(most\s+recent\s+call\s+last\)
      | ^\s*\w+Error:\s+                      # Python exception line
    )
    """,
    re.VERBOSE,
)

# Shell prompt markers — content that follows is shell output
_SHELL_PROMPT = re.compile(r"^\s*[\$#>]\s+", re.MULTILINE)


# --- Public API ---


def strip_code_blocks(text: str) -> str:
    """Remove fenced code blocks and inline code spans.

    Replaces matches with a single space so token positions shift but
    word boundaries stay intact.
    """
    without_fenced = _FENCED_CODE.sub(" ", text)
    return _INLINE_CODE.sub(" ", without_fenced)


def is_quoted_line(line: str) -> bool:
    """True if line starts with markdown blockquote marker."""
    return bool(_QUOTE_LINE.match(line))


def starts_with_reporting_verb(sentence: str) -> bool:
    """True if the sentence reports someone else's speech/opinion.

    Used to skip sentences like "I think I pushed something yesterday" —
    the hedge converts a claim into a report.
    """
    return bool(_REPORTING_PREFIX.match(sentence.strip()))


def is_log_line(line: str) -> bool:
    """True if line looks like log output (timestamp, level, trace)."""
    stripped = line.strip()
    if not stripped:
        return False
    return bool(
        _TIMESTAMP_LINE.search(line)
        or _LOG_LEVEL_PREFIX.match(line)
        or _STACK_TRACE_LINE.match(line)
        or _SHELL_PROMPT.match(line)
    )


def is_non_content(line: str) -> bool:
    """Combined check — True if line should be skipped entirely."""
    return is_quoted_line(line) or is_log_line(line)


def filter_content_lines(text: str) -> List[str]:
    """Return only content lines — strip code blocks, quotes, logs.

    Preserves line order; empty output means the whole text was
    non-content.
    """
    no_code = strip_code_blocks(text)
    kept = []
    for line in no_code.splitlines():
        if not is_non_content(line):
            kept.append(line)
    return kept


# --- Sentence splitter ---

# Crude but practical — splits on sentence-final punctuation followed by
# whitespace + capital letter or line end. Not perfect (abbreviations like
# "Dr." get split), but good enough for our short assistant messages and
# doesn't pull in a NLP library.
_SENTENCE_BOUNDARY = re.compile(
    r"""
    (?<=[.!?。！？])          # sentence-final punctuation (ASCII + Chinese)
    (?:["')\]]*)              # optional closing quote/paren
    \s*                       # whitespace (CJK often has no space after 。)
    (?=[A-ZА-ЯЁ\u4e00-\u9fff]) # next sentence starts with letter or CJK char
    """,
    re.VERBOSE,
)


def split_sentences(text: str) -> List[str]:
    """Split text into sentences. Naive but deterministic.

    Works on text already stripped of code/logs. Falls back to one
    sentence per paragraph if no clear boundaries.
    """
    # Normalize whitespace first
    normalized = re.sub(r"\s+", " ", text).strip()
    if not normalized:
        return []

    parts = _SENTENCE_BOUNDARY.split(normalized)
    # Further split on newlines between parts that weren't caught
    out = []
    for p in parts:
        for sub in p.split("\n"):
            sub = sub.strip()
            if sub:
                out.append(sub)
    return out


def prepare_for_analysis(text: str) -> List[str]:
    """Full pipeline: strip code/quotes/logs, split into sentences.

    Returns list of sentence strings ready for claim detection.
    """
    content_lines = filter_content_lines(text)
    combined = "\n".join(content_lines)
    return split_sentences(combined)
