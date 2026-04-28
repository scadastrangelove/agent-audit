"""Educational content suppressor — Fix 3 from grand-run analysis.

Heuristic: files that live inside known educational or translation
directories are almost never real agent-skill targets. They are
learning material, translated tutorials, or documentation examples.

When such a file also lacks the structural markers of an actual
skill (no SKILL.md frontmatter, no MCP manifest, no plugin descriptor),
demote rule-pack findings in that file by at least one severity level.

This is intentionally a path-based filter, not a content classifier —
cheap, predictable, easy to override per-project. If someone legitimately
puts a SKILL.md under /translations/ for a localised skill bundle, the
structural marker (SKILL.md with YAML frontmatter) still keeps the
finding alive.

Derived from grand-run on microsoft/generative-ai-for-beginners:
70 of 74 findings sat under /translations/*, 0 native findings.
"""
from __future__ import annotations

import re
from pathlib import Path

# Path fragments that reliably indicate educational / translation content.
# Matched against a case-insensitive PosixPath-style relative path.
_EDUCATIONAL_PATH_FRAGMENTS = [
    r"(?:^|/)translations?/",          # translations/, translation/
    r"(?:^|/)i18n/",
    r"(?:^|/)locales?/",               # locale/, locales/
    r"(?:^|/)docs?/(?:[a-z]{2,3})(?:[-_][A-Z][A-Za-z]+)?/",  # docs/zh-CN/, docs/fr/
    r"(?:^|/)tutorial[s]?/",
    r"(?:^|/)lesson[s]?/",
    r"(?:^|/)lab[s]?/",
    r"(?:^|/)examples?/(?:translations?|i18n|localized)/",
    # Beginner-labelled courseware (generative-ai-for-beginners, ml-for-beginners)
    r"(?:^|/)[\w-]*[-_]for[-_]beginners(?:/|$)",
]

_EDU_PATTERN = re.compile("|".join(_EDUCATIONAL_PATH_FRAGMENTS), re.IGNORECASE)

# Structural markers that override path-based suppression — if the file
# looks like a real skill despite its path, don't suppress.
_STRUCTURAL_SKILL_MARKERS = [
    re.compile(r"^---\s*\nname:\s*\S+", re.MULTILINE),        # SKILL.md frontmatter
    re.compile(r'"mcpServers"\s*:', re.IGNORECASE),            # MCP manifest
    re.compile(r'"commands"\s*:\s*\[', re.IGNORECASE),         # plugin descriptor
]


def is_educational_context(path: Path, text: str = "") -> bool:
    """Return True if the file lives in educational/translation context
    AND lacks structural skill markers.

    `path` is expected to be an absolute or project-relative path. We match
    on the forward-slash string form.
    """
    path_str = str(path).replace("\\", "/")
    if not _EDU_PATTERN.search(path_str):
        return False
    # If structural markers suggest this is a real skill despite its path,
    # don't suppress.
    for marker in _STRUCTURAL_SKILL_MARKERS:
        if marker.search(text or ""):
            return False
    return True


def demote_severity(severity_value: str) -> str:
    """Drop severity by one level. Ship floor is `info`."""
    order = ["info", "low", "medium", "high", "critical"]
    try:
        idx = order.index(severity_value)
    except ValueError:
        return severity_value
    return order[max(0, idx - 1)]
