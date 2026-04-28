"""Parse Codex CLI rollout logs from ~/.codex/sessions/YYYY/MM/DD/rollout-*.jsonl.

Format (per-line JSON):
    # First line — session metadata header
    {"session_id": "...", "timestamp": "...", ...}

    # User messages
    {"type": "event_msg", "payload": {"type": "user_message", "message": "..."}}

    # Assistant responses / tool calls
    {"type": "response_item", "payload": {
        "type": "message" | "function_call" | ...,
        "role": "assistant" | "user",
        "content": [{"type": "input_text" | "output_text", "text": "..."}],
        "name": "shell" | "apply_patch" | ...,
        "arguments": "{...}",
        "call_id": "..."
    }}

    # Function call results
    {"type": "response_item", "payload": {
        "type": "function_call_output",
        "call_id": "...",
        "output": "..."
    }}
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
    try:
        s = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


def _extract_text(content: Any) -> str:
    """Codex response items store content as list of blocks with text field."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = []
    for block in content:
        if isinstance(block, dict):
            text = block.get("text")
            if text:
                parts.append(str(text))
    return "\n".join(parts)


def _event_from_record(
    record: Dict[str, Any],
    *,
    session_id: str,
    turn_index: int,
    timestamp: datetime,
    cwd: Optional[str],
) -> Optional[Event]:
    rtype = record.get("type")
    payload = record.get("payload") or {}
    if not isinstance(payload, dict):
        return None

    common = {
        "session_id": session_id,
        "turn_index": turn_index,
        "timestamp": timestamp,
        "agent": AgentKind.CODEX,
        "cwd": cwd,
        "raw": record,
    }

    # User message wrapped in event_msg
    if rtype == "event_msg" and payload.get("type") == "user_message":
        return Event(
            **common,
            type=EventType.USER_MESSAGE,
            role="user",
            text=payload.get("message", ""),
        )

    if rtype != "response_item":
        return None

    ptype = payload.get("type")

    # Assistant or user message text
    if ptype == "message":
        role = payload.get("role", "assistant")
        text = _extract_text(payload.get("content"))
        if role == "user":
            return Event(
                **common,
                type=EventType.USER_MESSAGE,
                role="user",
                text=text,
            )
        return Event(
            **common,
            type=EventType.ASSISTANT_TEXT,
            role="assistant",
            text=text,
        )

    # Function / tool call
    if ptype == "function_call":
        raw_args = payload.get("arguments") or "{}"
        try:
            args = json.loads(raw_args) if isinstance(raw_args, str) else (raw_args or {})
        except json.JSONDecodeError:
            args = {"_raw": str(raw_args)}
        return Event(
            **common,
            type=EventType.TOOL_USE,
            role="assistant",
            tool_name=payload.get("name"),
            tool_input=args if isinstance(args, dict) else {"_value": args},
            tool_use_id=payload.get("call_id"),
        )

    # Shell calls can also appear as `local_shell_call` in newer versions
    if ptype in ("local_shell_call", "shell_call"):
        action = payload.get("action") or {}
        cmd = action.get("command") if isinstance(action, dict) else None
        return Event(
            **common,
            type=EventType.TOOL_USE,
            role="assistant",
            tool_name="shell",
            tool_input={"command": cmd} if cmd else action,
            tool_use_id=payload.get("call_id"),
        )

    # Tool / function call output
    if ptype in ("function_call_output", "local_shell_call_output", "shell_call_output"):
        output = payload.get("output")
        if isinstance(output, dict):
            output_str = output.get("content") or json.dumps(output)
        else:
            output_str = str(output or "")
        return Event(
            **common,
            type=EventType.TOOL_RESULT,
            role="tool",
            tool_result=output_str,
            tool_use_id=payload.get("call_id"),
        )

    return None


def parse_file(path: Path) -> Optional[Session]:
    """Parse a single Codex rollout JSONL file."""
    events: List[Event] = []
    session_id: Optional[str] = None
    cwd: Optional[str] = None
    first_ts: Optional[datetime] = None
    last_ts: Optional[datetime] = None
    turn_index = 0

    try:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    # v0.7.7: strict=False tolerates raw control chars
                    # (newlines/tabs) inside JSON string values. Real Codex
                    # JSONL occasionally writes unescaped \n inside long
                    # developer_instructions / user_instructions fields.
                    record = json.loads(line, strict=False)
                except json.JSONDecodeError:
                    continue
                if not isinstance(record, dict):
                    continue

                # v0.7.7 — Codex session cwd extraction (corrected)
                #
                # Real Codex JSONL schema confirmed from ~/.codex/sessions/*.jsonl:
                #   - line 1: type="session_meta", payload.cwd = "<abs-path>"
                #   - subsequent: type="turn_context", payload.cwd = "<abs-path>"
                #     (emitted at start of every turn; can change if user
                #     switches workdir mid-session)
                #
                # Previously we looked at record.get("cwd") on the top level,
                # which never matched Codex's actual layout — cwd is ALWAYS
                # nested in payload. Also previously we only read it from the
                # "header" heuristic (record with session_id but no type),
                # which matched nothing in real Codex files.
                record_type = record.get("type")
                payload = record.get("payload") if isinstance(record.get("payload"), dict) else None

                # Session metadata line — type=session_meta
                if record_type == "session_meta" and payload:
                    session_id = session_id or payload.get("session_id") or payload.get("sessionId")
                    cwd = cwd or payload.get("cwd") or payload.get("working_directory")
                    header_ts = _parse_timestamp(record.get("timestamp"))
                    if header_ts and first_ts is None:
                        first_ts = header_ts
                        last_ts = header_ts
                    # session_meta is pure metadata, not a real event
                    continue

                # Turn context — type=turn_context. Emitted at start of each
                # turn, always carries cwd. Use as first-wins fallback if
                # session_meta was missing or didn't include it.
                if record_type == "turn_context" and payload:
                    if not cwd:
                        cwd = payload.get("cwd") or payload.get("working_directory")
                    # turn_context is metadata framing, not an agent action —
                    # don't emit as a turn/event
                    continue

                # Legacy header shape — some older Codex versions emit
                # session-level fields on the record top level instead of
                # inside a typed payload. Keep the old path as a fallback.
                if ("session_id" in record or "sessionId" in record) and record_type is None:
                    session_id = session_id or record.get("session_id") or record.get("sessionId")
                    cwd = cwd or record.get("cwd") or record.get("working_directory")
                    header_ts = _parse_timestamp(record.get("timestamp"))
                    if header_ts and first_ts is None:
                        first_ts = header_ts
                        last_ts = header_ts
                    continue

                # Last-resort cwd: exec_command's workdir argument. Useful if
                # a Codex variant omits session_meta / turn_context entirely.
                if not cwd and payload and payload.get("type") == "function_call":
                    args_raw = payload.get("arguments")
                    if isinstance(args_raw, str):
                        try:
                            args = json.loads(args_raw, strict=False)
                            wd = args.get("workdir") if isinstance(args, dict) else None
                            if wd and isinstance(wd, str):
                                cwd = wd
                        except json.JSONDecodeError:
                            pass

                # Event records
                ts = _parse_timestamp(record.get("timestamp")) or last_ts or datetime.fromtimestamp(path.stat().st_mtime)
                if first_ts is None:
                    first_ts = ts
                last_ts = ts

                turn_index += 1
                event = _event_from_record(
                    record,
                    session_id=session_id or path.stem,
                    turn_index=turn_index,
                    timestamp=ts,
                    cwd=cwd,
                )
                if event:
                    events.append(event)
    except OSError:
        return None

    if not events:
        return None

    session_id = session_id or path.stem
    first_ts = first_ts or datetime.fromtimestamp(path.stat().st_mtime)
    last_ts = last_ts or first_ts

    return Session(
        session_id=session_id,
        agent=AgentKind.CODEX,
        source_file=path,
        started_at=first_ts,
        last_activity=last_ts,
        events=events,
        cwd=cwd,
    )
