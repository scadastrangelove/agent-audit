"""v0.8.2 — Cross-agent tool name normalization.

Problem: Codex uses `exec_command`/`write_stdin`/`apply_patch` while
Claude Code uses `Bash`/`Read`/`Write`/`Edit`. Detectors written for
Claude Code semantics silently skipped all Codex tool calls because
name match failed. Real-data v0.7.8 run: 108 Codex findings of which
79 were claim-detector based (text analysis only), ZERO were from
C2/C3/AG-04/AI-04/AD-02/AI-06 (all tool-call-based).

Solution: canonical tool name mapping applied at parse time. Each
Event gets a `canonical_tool` field in addition to its native
`tool_name`. Detectors can opt in to cross-agent via
`canonical_tool_of(event)` helper.

The canonical set is deliberately small — covers what existing
detectors actually check:

  - Bash       — shell execution
  - Read       — file read
  - Write      — file create/overwrite
  - Edit       — in-place file modification
  - BashStdin  — send input to running process (Codex polling)
  - Patch      — structured diff application
  - PlanUpdate — planning/task tracking (usually ignored)
  - WebSearch  — external search
  - WebFetch   — external HTTP fetch
  - Task       — sub-agent spawn (Claude Code's Task tool)

Native tool_name preserved for exact-name detectors and for reports.
"""
from __future__ import annotations

from typing import Any, Dict, Optional


# Exact-name map: native → canonical. Keys compared case-sensitively
# matching what parsers actually write.
_EXACT_MAP: Dict[str, str] = {
    # Claude Code (keys are canonical names by convention)
    "Bash":           "Bash",
    "Read":           "Read",
    "Write":          "Write",
    "Edit":           "Edit",
    "MultiEdit":      "Edit",
    "NotebookEdit":   "Edit",
    "Glob":           "Read",
    "Grep":           "Read",
    "WebSearch":      "WebSearch",
    "WebFetch":       "WebFetch",
    "Task":           "Task",
    "TodoWrite":      "PlanUpdate",
    "ExitPlanMode":   "PlanUpdate",

    # Codex CLI
    "exec_command":   "Bash",
    "shell":          "Bash",       # Codex legacy
    "write_stdin":    "BashStdin",  # polling / input to running process
    "apply_patch":    "Patch",
    "read_file":      "Read",
    "view_image":     "Read",
    "update_plan":    "PlanUpdate",
    "web_search":     "WebSearch",
    "web_fetch":      "WebFetch",

    # Cursor / Windsurf (speculative — these show up occasionally)
    "str_replace":    "Edit",
    "create_file":    "Write",
    "view":           "Read",
}


def canonical_for(tool_name: Optional[str]) -> Optional[str]:
    """Return canonical name for a native tool_name, or None if unknown.

    Unknown names → None. Detectors that want cross-agent behavior
    should check for the canonical name first, fall back to tool_name
    if they need exact semantics.
    """
    if not tool_name:
        return None
    # Exact match first
    if tool_name in _EXACT_MAP:
        return _EXACT_MAP[tool_name]
    # Case-insensitive fallback for parser variations
    lower = tool_name.lower()
    for native, canonical in _EXACT_MAP.items():
        if native.lower() == lower:
            return canonical
    return None


def is_shell_exec(event) -> bool:
    """True if event is a shell/bash command execution (any agent)."""
    return event.canonical_tool == "Bash"


def is_file_write(event) -> bool:
    """True if event is a file write/edit operation (any agent)."""
    return event.canonical_tool in ("Write", "Edit", "Patch")


def is_file_read(event) -> bool:
    """True if event is a file read operation (any agent)."""
    return event.canonical_tool == "Read"


def extract_command(event) -> Optional[str]:
    """Pull the shell command string from an event, handling native
    argument name variation: Claude uses `command`, Codex uses `cmd`."""
    if event.canonical_tool != "Bash":
        return None
    inp = event.tool_input or {}
    for key in ("command", "cmd", "script"):
        v = inp.get(key)
        if isinstance(v, str):
            return v
    return None


def extract_path(event) -> Optional[str]:
    """Pull the file path from a Read/Write/Edit event regardless of
    agent. Claude uses `file_path`, Codex varies."""
    if event.canonical_tool not in ("Read", "Write", "Edit", "Patch"):
        return None
    inp = event.tool_input or {}
    for key in ("file_path", "path", "filepath"):
        v = inp.get(key)
        if isinstance(v, str):
            return v
    return None
