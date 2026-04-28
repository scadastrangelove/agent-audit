"""Universal event model. All agent-specific parsers normalize to this."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class EventType(str, Enum):
    USER_MESSAGE = "user_message"
    ASSISTANT_TEXT = "assistant_text"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    SYSTEM = "system"


class AgentKind(str, Enum):
    CLAUDE_CODE = "claude_code"
    CODEX = "codex"
    OPENCLAW = "openclaw"
    UNKNOWN = "unknown"


class Event(BaseModel):
    """Single normalized event from an agent session."""

    # Core identity
    session_id: str
    turn_index: int
    timestamp: datetime
    agent: AgentKind

    # Event semantics
    type: EventType
    role: Literal["user", "assistant", "system", "tool"]

    # Content — one of these populated depending on type
    text: Optional[str] = None
    tool_name: Optional[str] = None
    tool_input: Optional[Dict[str, Any]] = None
    tool_result: Optional[str] = None
    tool_use_id: Optional[str] = None

    # v0.8.2: canonical_tool — normalized cross-agent tool name.
    # Codex uses `exec_command`, Claude Code uses `Bash` — both map to
    # canonical "Bash". Detectors that want cross-agent coverage check
    # canonical_tool; detectors that need exact semantics keep using
    # tool_name. Populated by parsers at parse time.
    canonical_tool: Optional[str] = None

    # Context
    cwd: Optional[str] = None
    git_branch: Optional[str] = None

    # Raw event for debugging / rules that need full access
    raw: Dict[str, Any] = Field(default_factory=dict, repr=False)


class Session(BaseModel):
    """Full agent session — ordered events plus metadata."""

    session_id: str
    agent: AgentKind
    source_file: Path
    started_at: datetime
    last_activity: datetime
    events: List[Event] = Field(default_factory=list, repr=False)

    # Derived
    cwd: Optional[str] = None
    git_branch: Optional[str] = None

    # Sub-agent lineage (Claude Code spawns Task sub-agents into subagents/ dirs)
    parent_session_id: Optional[str] = None
    is_subagent: bool = False

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def tool_calls(self) -> List[Event]:
        return [e for e in self.events if e.type == EventType.TOOL_USE]

    @property
    def user_messages(self) -> List[Event]:
        return [e for e in self.events if e.type == EventType.USER_MESSAGE]


# v0.8.2: cross-agent tool classification helpers. Detectors can call
# these instead of hard-coding (\"bash\", \"shell\") checks — they handle
# Claude Code's Bash, Codex's exec_command/shell, etc.

def is_bash_like(event) -> bool:
    """True if event is any shell/bash execution across agents."""
    if (event.tool_name or "").lower() in ("bash", "shell"):
        return True
    return getattr(event, "canonical_tool", None) == "Bash"


def is_write_like(event) -> bool:
    """True if event is any file-write operation across agents."""
    if (event.tool_name or "").lower() in ("write", "edit", "multiedit",
                                            "create_file", "str_replace",
                                            "apply_patch", "notebook_edit"):
        return True
    return getattr(event, "canonical_tool", None) in ("Write", "Edit", "Patch")


def is_read_like(event) -> bool:
    """True if event is any file-read operation across agents."""
    if (event.tool_name or "").lower() in ("read", "view", "read_file",
                                            "glob", "grep"):
        return True
    return getattr(event, "canonical_tool", None) == "Read"
