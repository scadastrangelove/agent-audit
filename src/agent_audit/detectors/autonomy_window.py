"""C3 — autonomy-window rules, v0.7.2 composite edition.

Previous version (v0.7.1 and earlier) had a single rule
`C3.autonomy-window-excess` that fired on tool-call count alone. Real-data
verification against 37 instances showed 100% false-positive rate: codex
verifier explained each time that "a long tool streak alone shows
autonomy, not abuse".

v0.7.2 splits into a family of composite rules:

  C3.autonomy-window-context       INFO     long window + CST — just a pointer
  C3.autonomy-with-sensitive-sink  MEDIUM   window + >=1 sensitive-path sink
  C3.autonomy-with-exfil-chain     HIGH     causality: source → sink with external content
  C3.autonomy-with-persistence     HIGH     window + persistence write

The INFO rule carries a Compact Sandbox Trace (from cst.py) that the
LLM verifier can use to reason about the window as a whole. INFO findings
are filtered out of verify by default (severity >= medium).

References:
  - ASAMM C3 — context-only, not alert
  - Agents of Chaos paper — composite signals beat single triggers
  - codex verification run (Apr 2026) — 37/37 FP on the single-trigger rule
"""
from __future__ import annotations

import json
from typing import Iterable, List

from ..cst import AutonomyWindow, autonomy_windows, build_window_trace, render_cst_markdown
from ..events import EventType, Session
from ..nlu import taint
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


MIN_WINDOW_SIZE = 15


def _iter_significant_windows(session: Session) -> Iterable[AutonomyWindow]:
    threshold = MIN_WINDOW_SIZE // 2 if session.is_subagent else MIN_WINDOW_SIZE
    for w in autonomy_windows(session):
        if w.tool_call_count >= threshold:
            yield w


def _cst_evidence(window: AutonomyWindow, session: Session) -> List[Evidence]:
    cst = build_window_trace(window.events, session)
    md = render_cst_markdown(cst)
    json_str = json.dumps(cst, indent=2, default=str)
    if len(json_str) > 2500:
        json_str = json_str[:2400] + "\n  ...(truncated)"
    return [
        Evidence(
            description="Compact Sandbox Trace (markdown)",
            source=session.source_file,
            session_id=session.session_id,
            turn_range=(window.start_turn, window.end_turn),
            snippet=md,
        ),
        Evidence(
            description="Compact Sandbox Trace (JSON)",
            source=session.source_file,
            session_id=session.session_id,
            turn_range=(window.start_turn, window.end_turn),
            snippet=json_str,
        ),
    ]


def _has_sink(window: AutonomyWindow, sink_type: taint.TaintSink) -> bool:
    for ev in window.events:
        cls = taint.classify_event(ev)
        if sink_type in cls.sinks:
            return True
    return False


def _exfil_chain_score(window: AutonomyWindow) -> float:
    chains = taint.find_chains_in_window(window.events)
    best = 0.0
    for ch in chains:
        source_types = {s for s, _ in ch.sources}
        if not (taint.TaintSource.WEB_RETRIEVED in source_types
                or taint.TaintSource.DOWNLOAD in source_types
                or taint.TaintSource.EXTERNAL_MEMORY in source_types):
            continue
        external_source = False
        for src, d in ch.sources:
            dest = d.get("destination") or d.get("src_destination", "")
            if dest in ("external", "user_content"):
                external_source = True
                break
        if not external_source:
            continue
        if ch.sink in (taint.TaintSink.SHELL_EXEC,):
            continue
        s = taint.score_chain(ch)
        if s > best:
            best = s
    return best


class AutonomyWindowContext(Rule):
    id = "C3.autonomy-window-context"
    title = "High-autonomy window (informational)"
    severity = Severity.INFO
    references = [
        "ASAMM C3 (Autonomy — context, not alert)",
        'Codex verification run (Apr 2026) — 37/37 FP on single-trigger C3',
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        for w in _iter_significant_windows(session):
            cst = build_window_trace(w.events, session)
            anomaly = cst.get("anomaly_score", 0.0)
            sub = cst.get("subgraph_scores", {})
            if anomaly >= 0.4 or any(v >= 0.4 for v in sub.values()):
                continue
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"Autonomy window with {w.tool_call_count} tool calls "
                    f"across turns {w.start_turn}–{w.end_turn}, anomaly "
                    f"score {anomaly}. Informational — not a vulnerability "
                    f"on its own, surfaced so a reviewer can skim the "
                    f"attached trace."
                ),
                evidence=_cst_evidence(w, session),
                remediation=(
                    "INFO findings don't need remediation. Follow up only "
                    "if the attached trace raises a specific question."
                ),
                references=self.references,
                needs_llm_verification=False,
            )


register_session_rule(AutonomyWindowContext())


class AutonomyWithSensitiveSink(Rule):
    id = "C3.autonomy-with-sensitive-sink"
    title = "Autonomy window + sensitive write"
    severity = Severity.MEDIUM
    references = [
        "ASAMM C3 + path sensitivity (Aegis)",
        "Composite signal — autonomy + sensitive write",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        for w in _iter_significant_windows(session):
            if not _has_sink(w, taint.TaintSink.SENSITIVE_WRITE):
                continue
            # Skip if more-severe rules will fire
            if _has_sink(w, taint.TaintSink.PERSISTENCE):
                continue
            if _exfil_chain_score(w) >= 0.5:
                continue
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.MEDIUM,
                summary=(
                    f"{w.tool_call_count}-step autonomy window "
                    f"(turns {w.start_turn}–{w.end_turn}) wrote to a "
                    f"sensitive path. Not inherently destructive, but the "
                    f"combination of length + target deserves review."
                ),
                evidence=_cst_evidence(w, session),
                remediation=(
                    "Confirm the write was intentional. If not, tighten "
                    "path-deny rules for the agent."
                ),
                references=self.references,
                needs_llm_verification=True,
            )


register_session_rule(AutonomyWithSensitiveSink())


class AutonomyWithExfilChain(Rule):
    id = "C3.autonomy-with-exfil-chain"
    title = "Autonomy window with untrusted-source → sensitive-sink chain"
    severity = Severity.HIGH
    references = [
        '"Agents of Chaos" CS10 (indirect prompt injection)',
        '"Agents of Chaos" CS1, CS6 (destructive cascade)',
        "Composite signal — causality over temporal slice",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        for w in _iter_significant_windows(session):
            score = _exfil_chain_score(w)
            if score < 0.5:
                continue
            sev = Severity.CRITICAL if score >= 0.8 else Severity.HIGH
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=sev,
                confidence=Confidence.HIGH,
                summary=(
                    f"{w.tool_call_count}-step autonomy window "
                    f"(turns {w.start_turn}–{w.end_turn}) contains a "
                    f"causality chain where untrusted external content "
                    f"preceded a sensitive action (score {round(score, 2)}). "
                    f"Structural signature of indirect prompt injection "
                    f"or content-driven destructive cascade."
                ),
                evidence=_cst_evidence(w, session),
                remediation=(
                    "Review the trace's taint chains. If external content "
                    "influenced a destructive or network action without "
                    "explicit user approval, treat as potential injection: "
                    "rotate exposed credentials, audit mutated resources, "
                    "add approval gates."
                ),
                references=self.references,
                needs_llm_verification=True,
            )


register_session_rule(AutonomyWithExfilChain())


class AutonomyWithPersistence(Rule):
    id = "C3.autonomy-with-persistence"
    title = "Autonomy window + persistence write"
    severity = Severity.HIGH
    references = [
        "Composite: C3 + AI-04",
        "ATT&CK T1546 (Event-Triggered Execution)",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        for w in _iter_significant_windows(session):
            if not _has_sink(w, taint.TaintSink.PERSISTENCE):
                continue
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"{w.tool_call_count}-step autonomy window "
                    f"(turns {w.start_turn}–{w.end_turn}) wrote to a "
                    f"persistence path. Long autonomy + persistence is "
                    f"the strongest combination for post-session "
                    f"backdoor installation."
                ),
                evidence=_cst_evidence(w, session),
                remediation=(
                    "Verify the persistence write was intended. If not, "
                    "treat as backdoor candidate — remove persistence, "
                    "rotate keys, audit outgoing network activity."
                ),
                references=self.references,
                needs_llm_verification=True,
            )


register_session_rule(AutonomyWithPersistence())
