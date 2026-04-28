"""Transparent audit log.

Every action the auditor takes is written here. Two purposes:
  1. Show the user exactly what we did (for trust).
  2. Collect data for self-improvement (rule false-positive rates etc).

Format is JSONL. Human-readable summary available via pretty_print().
"""
from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditAction:
    action: str                       # e.g. "read_file", "run_rule", "llm_query"
    target: str                       # what was touched
    timestamp: datetime = field(default_factory=datetime.now)
    outcome: str = "ok"               # ok | warn | error | blocked
    detail: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp"] = self.timestamp.isoformat()
        return data


class AuditLog:
    def __init__(self, path: Optional[Path] = None) -> None:
        self.path = path
        self.actions: List[AuditAction] = []
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            # Open in append mode, truncate at start of a new run
            path.write_text("", encoding="utf-8")

    def record(self, action: str, target: str, *, outcome: str = "ok", **detail: Any) -> None:
        entry = AuditAction(action=action, target=target, outcome=outcome, detail=detail)
        self.actions.append(entry)
        if self.path:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(entry.to_dict(), default=str) + "\n")

    def summary(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for a in self.actions:
            key = f"{a.action}:{a.outcome}"
            counts[key] = counts.get(key, 0) + 1
        return counts


def default_log_path() -> Path:
    """Log path under the user's data dir, one file per run."""
    base = Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share"))
    logs_dir = base / "agent-audit" / "logs"
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    return logs_dir / f"audit-{stamp}.jsonl"
