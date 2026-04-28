"""Compact Sandbox Trace — structured evidence bundle for autonomy windows.

For each high-autonomy window in a session, we produce a compact JSON
summary that captures:
  - sequence of actions (compressed control flow)
  - taint source → sink chains with causality scores (via nlu.taint)
  - sensitive paths touched (via Aegis classification)
  - network endpoints classified (localhost / known-agent / external / user-content)
  - first-person completion claims (via nlu.claim_detector)
  - anomaly score (fast heuristic)

The trace is designed to fit in ~1500-2000 tokens so a single LLM
verification prompt can reason about the whole window at once. It is
NOT a full provenance graph — see EDR_BACKLOG.md for what we don't have
on JSONL-only telemetry.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import List, Optional, Tuple

from .events import Event, EventType, Session
from .nlu import taint, claim_detector


# =============================================================================
# Control flow extraction
# =============================================================================


def _classify_action(event: Event, cls: taint.EventClassification) -> str:
    """Short label for a tool_use event: READ / WRITE / EXEC / NET / DESTR."""
    if event.type != EventType.TOOL_USE:
        return "?"

    # Sink-based classification takes priority for clarity
    if taint.TaintSink.DESTRUCTIVE in cls.sinks:
        return "DESTR"
    if taint.TaintSink.PERSISTENCE in cls.sinks:
        return "PERSIST"
    if taint.TaintSink.NETWORK_EGRESS in cls.sinks:
        return "NET-OUT"
    if taint.TaintSink.REPO_PUSH in cls.sinks:
        return "PUSH"
    if taint.TaintSink.PACKAGE_INSTALL in cls.sinks:
        return "INSTALL"
    if taint.TaintSink.SENSITIVE_WRITE in cls.sinks:
        return "WRITE!"
    if taint.TaintSource.SECRET_READ in cls.sources:
        return "READ!"
    if taint.TaintSource.WEB_RETRIEVED in cls.sources:
        return "NET-IN"
    if taint.TaintSource.DOWNLOAD in cls.sources:
        return "NET-IN"
    if taint.TaintSource.EXTERNAL_MEMORY in cls.sources:
        return "READ-EXT"

    # Plain tool types
    tool = (event.tool_name or "").lower()
    if tool in ("read", "view"):
        return "READ"
    if tool in ("write", "edit", "create_file", "str_replace_editor", "str_replace"):
        return "WRITE"
    if tool in ("bash", "shell"):
        return "EXEC"
    return tool.upper()[:8]


def _target_from_event(event: Event, cls: taint.EventClassification) -> str:
    """Extract a short target string (path, url, or cmd fragment)."""
    if cls.details.get("target"):
        return str(cls.details["target"])[:80]
    if cls.details.get("url"):
        return str(cls.details["url"])[:80]
    if cls.details.get("cmd"):
        return str(cls.details["cmd"])[:80]
    return ""


# =============================================================================
# Main CST builder
# =============================================================================


def build_window_trace(
    window_events: List[Event],
    session: Session,
    *,
    max_steps: int = 20,
    max_paths: int = 10,
    max_claims: int = 5,
) -> dict:
    """Build a Compact Sandbox Trace for a list of events from one window.

    Returns a dict suitable for JSON serialization. Designed for inclusion
    as an Evidence.snippet in a Finding.
    """
    if not window_events:
        return {"empty": True}

    tool_events = [e for e in window_events if e.type == EventType.TOOL_USE]
    text_events = [e for e in window_events
                   if e.type == EventType.ASSISTANT_TEXT and e.text]

    # Classify everything once
    classifications = [(e, taint.classify_event(e)) for e in window_events]

    # --- Duration ---
    duration_sec: Optional[int] = None
    if window_events:
        try:
            first_ts = window_events[0].timestamp
            last_ts = window_events[-1].timestamp
            duration_sec = int((last_ts - first_ts).total_seconds())
        except Exception:
            pass

    # --- Entry point: what triggered the autonomy ---
    entry_point = ""
    for e in window_events:
        if e.type == EventType.USER_MESSAGE and e.text:
            entry_point = e.text[:150]
            break

    # --- Compressed control flow ---
    control_flow = []
    tool_cls_pairs = [(e, c) for e, c in classifications if e.type == EventType.TOOL_USE]
    for i, (e, c) in enumerate(tool_cls_pairs[:max_steps], 1):
        step = {
            "step": i,
            "turn": e.turn_index,
            "action": _classify_action(e, c),
        }
        target = _target_from_event(e, c)
        if target:
            step["target"] = target
        control_flow.append(step)

    skipped = len(tool_cls_pairs) - max_steps
    if skipped > 0:
        control_flow.append({
            "step": "...",
            "note": f"+{skipped} more tool calls",
        })

    # --- Sensitive paths touched (deduplicated) ---
    sensitive_paths = {}
    for _, c in classifications:
        if "target" in c.details and "path_category" in c.details:
            path = c.details["target"]
            cat = c.details["path_category"]
            sensitive_paths[path] = cat
    sensitive_paths_list = [
        f"{p} ({cat})" for p, cat in list(sensitive_paths.items())[:max_paths]
    ]

    # --- Network endpoints ---
    network_endpoints = {}
    for e, c in classifications:
        # URL-based (WebFetch)
        if "destination" in c.details and "url" in c.details:
            url = c.details["url"]
            m = __import__("re").search(r"https?://([\w.-]+)", url)
            host = m.group(1).lower() if m else url[:40]
            network_endpoints[host] = c.details["destination"]
        # cmd-based (Bash)
        for key_host, key_dest in (
            ("src_host", "src_destination"),
            ("egress_host", "egress_destination"),
        ):
            if c.details.get(key_host):
                network_endpoints[c.details[key_host]] = c.details[key_dest]

    # --- Taint chains + subgraph scores ---
    taint_summary = taint.summarise_window(window_events)

    # --- First-person claims ---
    claims = []
    for te in text_events:
        for r in claim_detector.detect_claims(te.text or ""):
            if r.polarity == "positive" and r.label in ("claim", "uncertain"):
                claims.append({
                    "text": (te.text or "")[:120],
                    "label": r.label,
                    "category": r.category,
                    "verb": r.verb,
                    "score": r.score,
                })
        if len(claims) >= max_claims:
            break

    # --- Overall anomaly score (fast heuristic) ---
    anomaly = _compute_anomaly_score(
        control_flow, sensitive_paths, network_endpoints,
        taint_summary, claims,
    )

    return {
        "window_id": (
            f"{session.session_id}:{window_events[0].turn_index}-"
            f"{window_events[-1].turn_index}"
        ),
        "duration_sec": duration_sec,
        "tool_call_count": len(tool_events),
        "entry_point": entry_point,
        "anomaly_score": round(anomaly, 2),
        "subgraph_scores": taint_summary["subgraph_scores"],
        "control_flow": control_flow,
        "sensitive_paths": sensitive_paths_list,
        "network_endpoints": network_endpoints,
        "taint_chains": taint_summary["chains"],
        "first_person_claims": claims,
    }


def _compute_anomaly_score(
    control_flow: List[dict],
    sensitive_paths: dict,
    network_endpoints: dict,
    taint_summary: dict,
    claims: List[dict],
) -> float:
    """Fast heuristic 0.0-1.0. LLM does real judgment."""
    score = 0.0

    # Weight from taint subgraph scores — most important signal
    sub = taint_summary.get("subgraph_scores", {})
    score += sub.get("destructive", 0) * 0.3
    score += sub.get("persistence", 0) * 0.3
    score += sub.get("secret_access", 0) * 0.25
    score += sub.get("egress", 0) * 0.2
    score += sub.get("injection", 0) * 0.25

    # Sensitive paths count (capped contribution)
    if sensitive_paths:
        score += min(0.15, len(sensitive_paths) * 0.05)

    # External/user-content network destinations
    external_dests = sum(
        1 for v in network_endpoints.values()
        if v in ("external", "user_content")
    )
    if external_dests:
        score += min(0.15, external_dests * 0.08)

    # High-confidence claims without proportional tool activity
    confirmed_claims = sum(1 for c in claims if c.get("label") == "claim")
    if confirmed_claims and len([s for s in control_flow if s.get("step") != "..."]) < 3:
        score += 0.1  # claimed a lot, did little

    # Long windows by themselves don't add much
    if len(control_flow) > 25:
        score += 0.05

    return min(1.0, score)


# =============================================================================
# Markdown rendering (for human-readable .md report)
# =============================================================================


def render_cst_markdown(cst: dict, *, verbose: bool = False) -> str:
    """Render CST as compact Markdown for the .md report.

    Shows only the top signals for human readers. Full CST stays in .json.
    """
    if cst.get("empty"):
        return "_(empty window)_"

    lines = []
    wid = cst.get("window_id", "?")
    tcc = cst.get("tool_call_count", 0)
    dur = cst.get("duration_sec")
    anomaly = cst.get("anomaly_score", 0)

    dur_str = f"{dur}s" if dur is not None else "?"
    lines.append(f"**Window** `{wid}` — {tcc} tool calls in {dur_str}, anomaly {anomaly}")

    # Subgraph scores only if nonzero
    sub = cst.get("subgraph_scores", {})
    nonzero = {k: v for k, v in sub.items() if v > 0.1}
    if nonzero:
        parts = [f"{k}={v}" for k, v in sorted(nonzero.items(), key=lambda x: -x[1])]
        lines.append(f"- Risk categories: {', '.join(parts)}")

    # Top taint chains (max 3)
    chains = cst.get("taint_chains", [])
    if chains:
        lines.append("- Taint chains:")
        for ch in chains[:3]:
            sources = ", ".join(ch.get("sources", [])[:3])
            sink = ch.get("sink", "?")
            tgt = ch.get("sink_target", "")[:60]
            lines.append(f"  - `{sources}` → `{sink}` ({tgt}) · score {ch.get('score', 0)}")

    # Top control flow (max 5)
    cf = cst.get("control_flow", [])
    if cf:
        lines.append("- Action sequence:")
        for step in cf[:5]:
            if step.get("step") == "...":
                lines.append(f"  - _{step['note']}_")
            else:
                action = step.get("action", "?")
                target = step.get("target", "")[:60]
                lines.append(f"  - `{action}` {target}")
        if len(cf) > 5:
            lines.append(f"  - _(+{len(cf) - 5} more steps)_")

    # Claims (if any)
    claims = cst.get("first_person_claims", [])
    if claims:
        lines.append(f"- Completion claims: {len(claims)} positive")
        for c in claims[:2]:
            lines.append(f"  - {c['label']}: _{c['text'][:80]}_")

    # Sensitive paths (compact)
    sp = cst.get("sensitive_paths", [])
    if sp:
        lines.append(f"- Sensitive paths touched: {len(sp)}")
        for p in sp[:3]:
            lines.append(f"  - `{p}`")

    return "\n".join(lines)


# =============================================================================
# Window slicing (autonomy windows from a session)
# =============================================================================


@dataclass
class AutonomyWindow:
    """A span of events between user messages."""
    start_turn: int
    end_turn: int
    events: List[Event]

    @property
    def tool_call_count(self) -> int:
        return sum(1 for e in self.events if e.type == EventType.TOOL_USE)


def autonomy_windows(session: Session) -> List[AutonomyWindow]:
    """Split session events into autonomy windows by user messages.

    Each window starts with a user message (if there is one) and ends
    before the next user message. Includes the trailing span if any.
    """
    windows: List[AutonomyWindow] = []
    if not session.events:
        return windows

    current: List[Event] = []
    for ev in session.events:
        if ev.type == EventType.USER_MESSAGE and current:
            windows.append(AutonomyWindow(
                start_turn=current[0].turn_index,
                end_turn=current[-1].turn_index,
                events=current,
            ))
            current = []
        current.append(ev)

    if current:
        windows.append(AutonomyWindow(
            start_turn=current[0].turn_index,
            end_turn=current[-1].turn_index,
            events=current,
        ))

    return windows
