"""Parse Claude Code session logs from ~/.claude/projects/**/*.jsonl.

Format (per-line JSON):
    {
      "type": "user" | "assistant" | "system",
      "sessionId": "<uuid>",
      "cwd": "/path",
      "gitBranch": "main",
      "timestamp": "ISO-8601",
      "message": {
        "role": "user" | "assistant",
        "content": [
          {"type": "text", "text": "..."},
          {"type": "tool_use", "name": "...", "input": {...}, "id": "..."},
          {"type": "tool_result", "tool_use_id": "...", "content": "..."}
        ]
      }
    }

The format is fairly stable but we tolerate missing fields.
"""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..events import AgentKind, Event, EventType, Session


def _parse_timestamp(value: Any) -> Optional[datetime]:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        # Handle both "Z" and "+00:00" suffixes
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _extract_content_blocks(message: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Message content can be a string or a list of content blocks."""
    content = message.get("content")
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return content
    return []


def _event_from_block(
    block: Dict[str, Any],
    *,
    session_id: str,
    turn_index: int,
    timestamp: datetime,
    role: str,
    cwd: Optional[str],
    git_branch: Optional[str],
    raw: Dict[str, Any],
) -> Optional[Event]:
    btype = block.get("type")
    common = {
        "session_id": session_id,
        "turn_index": turn_index,
        "timestamp": timestamp,
        "agent": AgentKind.CLAUDE_CODE,
        "cwd": cwd,
        "git_branch": git_branch,
        "raw": raw,
    }

    if btype == "text":
        return Event(
            **common,
            type=EventType.USER_MESSAGE if role == "user" else EventType.ASSISTANT_TEXT,
            role=role,  # type: ignore[arg-type]
            text=block.get("text", ""),
        )
    if btype == "tool_use":
        return Event(
            **common,
            type=EventType.TOOL_USE,
            role="assistant",
            tool_name=block.get("name"),
            tool_input=block.get("input") or {},
            tool_use_id=block.get("id"),
        )
    if btype == "tool_result":
        result_content = block.get("content")
        if isinstance(result_content, list):
            # result content can itself be content blocks
            texts = [c.get("text", "") for c in result_content if isinstance(c, dict) and c.get("type") == "text"]
            result_str = "\n".join(texts)
        else:
            result_str = str(result_content) if result_content is not None else ""
        return Event(
            **common,
            type=EventType.TOOL_RESULT,
            role="tool",
            tool_result=result_str,
            tool_use_id=block.get("tool_use_id"),
        )
    return None


def parse_file(path: Path) -> Optional[Session]:
    """Parse a single Claude Code session JSONL file.

    Returns None for empty or entirely invalid files. Skips unparseable lines
    but keeps going — agent logs sometimes have partial/corrupt lines.
    """
    events: List[Event] = []
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    git_branch: Optional[str] = None
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    turn_index = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line_no, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Extract top-level fields
                if session_id is None:
                    session_id = record.get("sessionId") or path.stem
                cwd = record.get("cwd") or cwd
                git_branch = record.get("gitBranch") or git_branch
                ts = _parse_timestamp(record.get("timestamp")) or datetime.fromtimestamp(path.stat().st_mtime)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                message = record.get("message")
                if not isinstance(message, dict):
                    # system event or meta record
                    continue
                role = message.get("role", "system")
                blocks = _extract_content_blocks(message)
                turn_index += 1
                for block in blocks:
                    if not isinstance(block, dict):
                        continue
                    event = _event_from_block(
                        block,
                        session_id=session_id,
                        turn_index=turn_index,
                        timestamp=ts,
                        role=role,
                        cwd=cwd,
                        git_branch=git_branch,
                        raw=record,
                    )
                    if event:
                        events.append(event)
    except OSError:
        return None

    if not events or session_id is None or first_ts is None or last_ts is None:
        return None

    # Detect sub-agent sessions by their filesystem path.
    # Claude Code stores sub-agent (Task-tool) transcripts at:
    #   ~/.claude/projects/<proj>/<parent-uuid>/subagents/agent-<id>.jsonl
    is_subagent = False
    parent_session_id: Optional[str] = None
    parts = path.parts
    if "subagents" in parts:
        is_subagent = True
        idx = parts.index("subagents")
        # The parent session UUID is the directory just above "subagents"
        if idx > 0:
            parent_dir = parts[idx - 1]
            # The parent dir name is the parent session UUID (optionally with .jsonl
            # extension stripped by Claude Code — it's just the UUID here).
            parent_session_id = parent_dir

    return Session(
        session_id=session_id,
        agent=AgentKind.CLAUDE_CODE,
        source_file=path,
        started_at=first_ts,
        last_activity=last_ts,
        events=events,
        cwd=cwd,
        git_branch=git_branch,
        is_subagent=is_subagent,
        parent_session_id=parent_session_id,
    )
