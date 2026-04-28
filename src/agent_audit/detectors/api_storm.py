"""resource.api-storm — agent pounded a single endpoint/tool with many calls.

Complements resource.unbounded-loop (v0.7): that detector requires
identical tool+args for every call. This one captures the retry-with-
changing-params case — agent keeps hitting the SAME endpoint with
DIFFERENT arguments, e.g.:

  - searching a DB: query1, query2, query3... (50k queries)
  - retrying an API with varying parameters
  - walking a ID space: GET /users/1, /users/2, ..., /users/50000

Motivated by the April 2026 r/AI_Agents case: agent crashed production
DB via ~50,000 internal API requests over an hour, also ran up an
OpenAI bill. Not destructive per se — but availability impact plus
cost.

Detection:
  - Group tool_use events by (tool_name, endpoint) where endpoint is
    URL path/host, DB name, or first N path segments
  - If a single group exceeds MIN_STORM_COUNT within one autonomy window
    → finding

Thresholds higher than unbounded-loop because varying-params looks
more like legitimate batch work, so we need stronger signal to flag.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Iterable, List, Optional, Tuple

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


# Extract the endpoint "kind" from a tool_use event — coarse grouping so
# that varying query params still collapse to the same key.

_URL_HOST_PATH = re.compile(r"https?://([\w.-]+)(/[^?\s&|;'\"]*)?")


def _endpoint_key(event: Event) -> Optional[str]:
    """Return a coarse endpoint key for grouping, or None if we can't
    tell. Uses (tool_name, normalized_url_or_cmd_prefix).
    """
    if event.type != EventType.TOOL_USE:
        return None
    tool = (event.tool_name or "").lower()
    # v0.8.2: canonical tool cross-agent
    canonical = getattr(event, "canonical_tool", None)

    # WebFetch / WebSearch — group by host + path (ignore query)
    if (tool in ("webfetch", "web_fetch", "websearch", "web_search", "fetch")
            or canonical in ("WebFetch", "WebSearch")):
        for k in ("url", "uri", "query"):
            v = (event.tool_input or {}).get(k)
            if isinstance(v, str):
                m = _URL_HOST_PATH.search(v)
                if m:
                    host = m.group(1)
                    path = m.group(2) or "/"
                    # Normalize trailing numeric IDs in path — /users/123 → /users/:id
                    path_norm = re.sub(r"/\d+", "/:id", path)
                    return f"{tool}:{host}{path_norm}"
                return f"{tool}:{v[:40]}"
        return f"{tool}:?"

    # Bash with curl/wget — same normalization
    if tool in ("bash", "shell") or canonical == "Bash":
        cmd = ""
        for k in ("command", "cmd", "script"):
            v = (event.tool_input or {}).get(k)
            if isinstance(v, str):
                cmd = v
                break
        if not cmd:
            return None
        m = re.search(r"\b(?:curl|wget|http|httpie?)\s+[^|&;]*?(https?://\S+)", cmd)
        if m:
            url = m.group(1)
            um = _URL_HOST_PATH.search(url)
            if um:
                host = um.group(1)
                path = um.group(2) or "/"
                path_norm = re.sub(r"/\d+", "/:id", path)
                return f"curl:{host}{path_norm}"
        # DB CLI — psql/mysql/sqlite3 — group by subcommand "first line"
        m = re.search(r"\b(?:psql|mysql|sqlite3|redis-cli|mongosh)\b", cmd)
        if m:
            tool_name = m.group(0).lower()
            return f"dbcli:{tool_name}"
        # Not a groupable case — skip
        return None

    # Generic: tool_name alone — less useful, skip
    return None


def _autonomy_windows(session: Session):
    """Yield lists of events split by user messages."""
    current: List[Event] = []
    for ev in session.events:
        if ev.type == EventType.USER_MESSAGE and current:
            yield current
            current = []
        current.append(ev)
    if current:
        yield current


class APIStorm(Rule):
    """Excessive calls to a single endpoint with varying parameters.

    Distinct from unbounded-loop (same args repeated) — this catches
    the N*unique-args case where the signature differs each time but
    the target is the same.
    """

    id = "resource.api-storm"
    title = "Endpoint pounded with many rapid calls"
    severity = Severity.HIGH
    references = [
        "Reddit r/AI_Agents (Apr 2026) — agent ran ~50k internal API "
        "requests in one hour, crashed prod DB, $$ OpenAI bill",
        "Related: Agents of Chaos CS4/CS5 (loops), but pattern differs",
    ]

    # Threshold — varying params look more legitimate than identical args,
    # so we need higher count to flag.
    MIN_STORM_COUNT = 25       # MEDIUM at this many
    SEV_HIGH_COUNT = 100       # HIGH
    SEV_CRITICAL_COUNT = 500   # CRITICAL

    def check_session(self, session: Session) -> Iterable[Finding]:
        for window in _autonomy_windows(session):
            tool_events = [e for e in window if e.type == EventType.TOOL_USE]
            if len(tool_events) < self.MIN_STORM_COUNT:
                continue

            key_counts = Counter()
            first_by_key = {}
            last_by_key = {}
            for ev in tool_events:
                k = _endpoint_key(ev)
                if not k:
                    continue
                key_counts[k] += 1
                first_by_key.setdefault(k, ev)
                last_by_key[k] = ev

            for key, count in key_counts.items():
                if count < self.MIN_STORM_COUNT:
                    continue

                first_ev = first_by_key[key]
                last_ev = last_by_key[key]
                span = last_ev.turn_index - first_ev.turn_index
                # Require span > 10 turns to avoid one-shot batches looking like storms
                if span < 10:
                    continue

                sev = Severity.MEDIUM
                if count >= self.SEV_CRITICAL_COUNT:
                    sev = Severity.CRITICAL
                elif count >= self.SEV_HIGH_COUNT:
                    sev = Severity.HIGH

                # Sub-agent downgrade
                if session.is_subagent:
                    if sev == Severity.CRITICAL:
                        sev = Severity.HIGH
                    elif sev == Severity.HIGH:
                        sev = Severity.MEDIUM

                # Count how many of the calls are unique-arg vs repeat-arg
                # (helps LLM understand whether this is "same query 100x"
                # vs "walking an ID space")
                unique_inputs = set()
                for ev in tool_events:
                    if _endpoint_key(ev) != key:
                        continue
                    input_str = str(ev.tool_input)[:200]
                    unique_inputs.add(input_str)
                uniqueness = len(unique_inputs) / max(count, 1)

                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Endpoint `{key}` was called {count} times across "
                        f"{span} turns in one autonomy window. "
                        f"Uniqueness of arguments: "
                        f"{int(uniqueness * 100)}% "
                        f"({len(unique_inputs)} distinct arg sets out of "
                        f"{count} calls). This pattern caused the April "
                        f"2026 prod DB crash via 50k internal API hits. "
                        f"Availability + cost impact regardless of "
                        f"destructive intent."
                    ),
                    evidence=[
                        Evidence(
                            description=f"Endpoint storm: {key}",
                            source=session.source_file,
                            session_id=session.session_id,
                            turn_range=(first_ev.turn_index, last_ev.turn_index),
                            snippet=f"count={count} span={span}turns unique_args={len(unique_inputs)}",
                        ),
                    ],
                    remediation=(
                        "If the storm was intentional (e.g. walking a "
                        "dataset) — add rate limiting and max-iteration "
                        "guards. If unintentional — the agent is likely "
                        "in a retry loop where each response feeds the "
                        "next request. Add circuit-breaker: if the same "
                        "endpoint returns >N times in window, stop and "
                        "ask the user. For Claude Code / Codex, consider "
                        "setting a turn budget per session in the config."
                    ),
                    references=self.references,
                    needs_llm_verification=True,
                )


register_session_rule(APIStorm())
