# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Session-mode rule executor — Roadmap item M1.

Closes the diagonal between forensic and static execution modes:
- BEFORE: forensic scanner (`scanner.py`) ran 27 native detectors only;
  rule packs (310 rules) were dead for forensic analysis even when they
  declared `audit_surface: [session_user_input, session_tool_output, ...]`.
- AFTER:  forensic scanner additionally runs all rule-pack rules whose
  audit_surface includes at least one `session_*` value, against the
  matching fields of `Session.events[]`.

This module is the bridge. It is deliberately narrow — it does NOT
introduce cross-mode signal flow (that's M2, deferred). It just feeds
the existing rule-pack rules into the existing session-rule machinery
so they actually run.

## Mapping from declaration to runtime

YAML rules declare `audit_surface` (which surfaces they apply to) and
`detection.conditions[].field` (which event field carries the text to
match). The mapping below is the single source of truth for both:

| audit_surface          | event.role/type filter        | text source     |
|------------------------|-------------------------------|-----------------|
| session_user_input     | role=user                     | event.text      |
| session_agent_output   | role=assistant                | event.text      |
| session_tool_call      | type=TOOL_USE                 | tool name+args  |
| session_tool_args      | type=TOOL_USE                 | tool_input json |
| session_tool_output    | type=TOOL_RESULT              | event.tool_result |
| session_tool_response  | type=TOOL_RESULT              | event.tool_result |
| session_event_stream   | (any event)                   | full event repr |

The mapping accommodates ATR conditions whose `field` matches one of:
`user_input`, `agent_output`, `tool_args`, `tool_response`, `tool_name`.
A rule with surface `session_user_input` and condition `field: user_input`
runs the regex against `event.text` for events where `role == "user"`.
A rule with surface `session_tool_output` and condition
`field: tool_response` runs against `event.tool_result` for tool-result
events. Conditions with `field: content` are surface-agnostic — they
run against whichever surface text is currently being inspected.

## Adapter contract

`session_rules_from_packs()` returns a list of `Rule` objects (the
existing detector base class). Each adapted Rule wraps one rule-pack
rule and implements `check_session()` by walking session.events and
running the rule's compiled patterns against the appropriate field.

This means the existing `_SESSION_RULES` registry mechanism in
`rules.py` is reused — no new orchestrator needed in `scanner.py`. The
adapter just registers itself once at scanner startup.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Callable, Iterable, List, Optional, Set

from .events import Event, EventType, Session
from .knowledge.rule_pack_loader import RulePackRule, load_all_rules
from .rules import (
    Confidence,
    DetectionMode,
    Evidence,
    Finding,
    Rule,
    Severity,
)


# ----------------------------------------------------------------------------
# Surface filter — which rules apply to forensic mode at all
# ----------------------------------------------------------------------------

# Rule-pack surfaces this executor knows how to feed events into.
# A rule with at least one of these in its audit_surface will be adapted.
# Other session_* surfaces declared by future rule packs will be ignored
# until we add explicit handlers — the executor never runs a rule it
# doesn't understand.
SESSION_SURFACES: Set[str] = {
    "session_user_input",
    "session_agent_output",
    "session_tool_call",
    "session_tool_args",
    "session_tool_output",
    "session_tool_response",
    "session_event_stream",
}


# ----------------------------------------------------------------------------
# Field extractors — surface name → callable that yields (event, text) pairs
# ----------------------------------------------------------------------------

def _events_for_surface(session: Session, surface: str) -> Iterable[tuple]:
    """Yield (event, text) pairs from session.events that match surface.

    The `text` is the string the rule's regex should run against. When a
    surface implies a structured field (tool_input dict), we serialize to
    a stable string — sorted JSON, no whitespace — so regexes that look
    for argument keys work naturally.
    """
    for event in session.events:
        if surface == "session_user_input":
            if event.role == "user" and event.text:
                yield event, event.text
        elif surface == "session_agent_output":
            if event.role == "assistant" and event.text:
                yield event, event.text
        elif surface == "session_tool_call":
            if event.type == EventType.TOOL_USE:
                # Combine name + serialized args so a rule looking for either
                # part fires once. Sorted-keys JSON keeps it deterministic.
                tool_text = (event.tool_name or "") + " " + _serialize_input(event.tool_input)
                if tool_text.strip():
                    yield event, tool_text
        elif surface == "session_tool_args":
            if event.type == EventType.TOOL_USE and event.tool_input:
                serialized = _serialize_input(event.tool_input)
                if serialized:
                    yield event, serialized
        elif surface in ("session_tool_output", "session_tool_response"):
            if event.type == EventType.TOOL_RESULT and event.tool_result:
                yield event, event.tool_result
        elif surface == "session_event_stream":
            # Full event surface — concatenate the meaningful text fields.
            # Used by rules that look for cross-field patterns (e.g. tool
            # name AND argument value together).
            parts = []
            if event.text:
                parts.append(event.text)
            if event.tool_name:
                parts.append(event.tool_name)
            if event.tool_input:
                parts.append(_serialize_input(event.tool_input))
            if event.tool_result:
                parts.append(event.tool_result)
            joined = "\n".join(parts)
            if joined:
                yield event, joined


def _serialize_input(tool_input) -> str:
    """Stable string form of tool_input dict for regex matching."""
    if not tool_input:
        return ""
    if isinstance(tool_input, str):
        return tool_input
    try:
        return json.dumps(tool_input, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(tool_input)


# ----------------------------------------------------------------------------
# Adapter: wrap a RulePackRule as a Rule object
# ----------------------------------------------------------------------------

class RulePackSessionRule(Rule):
    """Adapter that runs a single rule-pack rule's regex against session events.

    One adapter instance per RulePackRule. The adapter snapshots the
    pre-compiled patterns from the loader, so re-loading rule packs at
    runtime requires re-creating the adapters (handled by callers).
    """

    def __init__(self, pack_rule: RulePackRule):
        self._pack = pack_rule
        # The 'id' field is the public identifier shown in findings.
        # Use the same shape as native detectors: rule-pack rules already
        # have agent_audit_id like "atr.prompt-injection.system-prompt-override".
        self.id = pack_rule.agent_audit_id
        self.title = pack_rule.title
        self.severity = pack_rule.severity
        # Surfaces this adapter actually handles (intersection of declared
        # surfaces and the executor's known set).
        self._applicable_surfaces = pack_rule.audit_surface & SESSION_SURFACES

    def check_session(
        self,
        session: Session,
        mode: DetectionMode = DetectionMode.BALANCED,
    ) -> List[Finding]:
        if not self._applicable_surfaces or not self._pack.patterns:
            return []

        findings: List[Finding] = []
        seen_event_ids: Set[int] = set()  # one finding per (rule, event)

        for surface in self._applicable_surfaces:
            for event, text in _events_for_surface(session, surface):
                # De-dup: a rule can declare multiple surfaces that resolve
                # to the same event (e.g. session_tool_output AND
                # session_event_stream both inspect a TOOL_RESULT). Without
                # this guard we'd emit two findings for one logical hit.
                event_key = id(event)
                if event_key in seen_event_ids:
                    continue

                # Exclude gate first: if any exclude pattern matches, skip
                if any(exc.search(text) for exc in self._pack.exclude_patterns):
                    continue

                m = None
                for pat in self._pack.patterns:
                    m = pat.search(text)
                    if m:
                        break
                if m is None:
                    continue

                seen_event_ids.add(event_key)
                findings.append(self._make_finding(session, event, surface, text, m))

        return findings

    def _make_finding(
        self,
        session: Session,
        event: Event,
        surface: str,
        text: str,
        match: re.Match,
    ) -> Finding:
        snippet = _snippet_around(text, match, context=60)
        refs: List[str] = []
        if self._pack.asamm_primary:
            refs.append(f"ASAMM:{self._pack.asamm_primary}")
        for s in self._pack.asamm_secondary:
            refs.append(f"ASAMM:{s}")
        for kind, values in (self._pack.references or {}).items():
            if isinstance(values, list):
                for v in values[:3]:
                    refs.append(f"{kind}:{v}")
        refs.append(f"upstream:{self._pack.source_tool}:{self._pack.source_original_id}")
        refs.append(f"surface:{surface}")
        refs.append("mode:forensic-from-rule-pack")
        return Finding(
            rule_id=self._pack.agent_audit_id,
            title=self._pack.title,
            severity=self._pack.severity,
            confidence=Confidence.MEDIUM,
            summary=f"[{self._pack.source_tool}] {self._pack.title} — matched in {surface} at turn {event.turn_index}",
            evidence=[
                Evidence(
                    description=f"Pattern matched in {surface}",
                    session_id=session.session_id,
                    turn_range=(event.turn_index, event.turn_index),
                    snippet=snippet,
                )
            ],
            remediation=self._pack.remediation or None,
            references=refs,
            needs_llm_verification=(self._pack.severity in (Severity.MEDIUM, Severity.LOW)),
        )


def _snippet_around(text: str, match: re.Match, context: int = 60) -> str:
    """Mirror project_scanner._snippet_around for symmetric reporting."""
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    s = text[start:end].replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return (("…" + s) if start > 0 else s) + (("…") if end < len(text) else "")


# ----------------------------------------------------------------------------
# Entry point — gather all session-applicable rule-pack rules as Rules
# ----------------------------------------------------------------------------

def session_rules_from_packs(
    rules: Optional[List[RulePackRule]] = None,
) -> List[RulePackSessionRule]:
    """Return adapter instances for every rule-pack rule that declares
    at least one session_* surface and has at least one compiled pattern.

    The forensic scanner can register these alongside native detectors,
    or can run them directly without registry registration. Both paths
    use the same `Rule.check_session()` contract.

    If `rules` is None, loads from `load_all_rules()`. Pass an explicit
    list during tests to avoid the full disk walk.
    """
    rules = rules if rules is not None else load_all_rules()
    adapted: List[RulePackSessionRule] = []
    for r in rules:
        if not (r.audit_surface & SESSION_SURFACES):
            continue
        if not r.patterns:
            # Rule has session surfaces but no patterns — likely a
            # pure-references rule still being authored. Skip silently.
            continue
        adapted.append(RulePackSessionRule(r))
    return adapted


def run_session_rule_packs(
    session: Session,
    *,
    rules: Optional[List[RulePackRule]] = None,
    mode: DetectionMode = DetectionMode.BALANCED,
) -> List[Finding]:
    """Convenience: adapt and run in one call. Used by scanner.py.

    Equivalent to:
        adapters = session_rules_from_packs(rules)
        return [f for a in adapters for f in a.check_session(session, mode)]

    Errors in any single rule are caught and emitted as a low-severity
    error finding, mirroring `run_session_rules()` behavior. A buggy
    rule must not abort the scan.
    """
    findings: List[Finding] = []
    for adapter in session_rules_from_packs(rules):
        try:
            findings.extend(adapter.check_session(session, mode=mode))
        except Exception as exc:  # noqa: BLE001
            findings.append(
                Finding(
                    rule_id=f"{adapter.id}.error",
                    title=f"Rule {adapter.id} failed",
                    severity=Severity.LOW,
                    confidence=Confidence.LOW,
                    summary=f"Internal error during rule-pack execution: {exc}",
                )
            )
    return findings
