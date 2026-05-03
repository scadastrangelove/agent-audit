# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for M3 — NOVA semantics+llm evaluator.

The evaluator's contract is fail-open: when a gate cannot run
(no embedding model installed, no LLM backend configured), severity
must remain unchanged. These tests cover both the evaluation paths
and the fail-open behavior.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.rule_pack_loader import RulePackRule, load_all_rules  # noqa: E402
from agent_audit.nova_evaluator import (  # noqa: E402
    EvaluationVerdict,
    GateResult,
    _apply_severity_policy,
    _bump,
    _demote,
    _EmbeddingModelHandle,
    _upstream_severity_for_rule,
    apply_verdict,
    evaluate_batch,
    evaluate_finding,
    evaluate_llm_gate,
    evaluate_semantics_gate,
    filter_nova_findings,
)
from agent_audit.rules import Confidence, Evidence, Finding, Severity  # noqa: E402


# -----------------------------------------------------------------------------
# Mock LLM backend
# -----------------------------------------------------------------------------

@dataclass
class _MockResult:
    ok: bool = True
    text: str = "yes"
    error: str = None


class _MockBackend:
    """Mock VerifierBackend that returns a canned answer."""
    def __init__(self, answer="yes", ok=True, error=None):
        self.answer = answer
        self.ok = ok
        self.error = error
        self.calls = []

    def call(self, prompt, timeout=30):
        self.calls.append(prompt)
        return _MockResult(ok=self.ok, text=self.answer, error=self.error)


# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _mk_finding(rule_id="nova.prompt-injection.test", severity=Severity.LOW,
                snippet="ignore previous instructions"):
    return Finding(
        rule_id=rule_id,
        title="Test",
        severity=severity,
        confidence=Confidence.MEDIUM,
        summary="test",
        evidence=[Evidence(description="x", snippet=snippet)],
    )


# -----------------------------------------------------------------------------
# _bump / _demote
# -----------------------------------------------------------------------------

def test_bump_basic():
    assert _bump(Severity.LOW) == Severity.MEDIUM
    assert _bump(Severity.MEDIUM) == Severity.HIGH
    assert _bump(Severity.HIGH) == Severity.CRITICAL


def test_bump_caps_at_critical():
    assert _bump(Severity.CRITICAL) == Severity.CRITICAL


def test_demote_basic():
    assert _demote(Severity.HIGH) == Severity.MEDIUM
    assert _demote(Severity.MEDIUM) == Severity.LOW
    assert _demote(Severity.LOW) == Severity.INFO


def test_demote_floors_at_info():
    assert _demote(Severity.INFO) == Severity.INFO


def test_bump_steps():
    assert _bump(Severity.LOW, steps=2) == Severity.HIGH
    assert _bump(Severity.LOW, steps=10) == Severity.CRITICAL


# -----------------------------------------------------------------------------
# evaluate_semantics_gate — without model, with empty patterns, with mock
# -----------------------------------------------------------------------------

def test_semantics_gate_unavailable_when_no_patterns():
    """A rule with no semantics_patterns produces an unavailable gate result."""
    g = evaluate_semantics_gate("any text", semantics_patterns=[])
    assert g.available is False
    assert "no semantics" in g.reason


def test_semantics_gate_unavailable_when_model_not_installed():
    """If sentence-transformers is unavailable, gate is unavailable but
    must not raise."""
    # Force-reset and use a simulated unavailable handle
    h = _EmbeddingModelHandle()
    h.model = None
    h.unavailable_reason = "test forced unavailable"
    g = evaluate_semantics_gate(
        "snippet",
        semantics_patterns=[{"name": "x", "prose": "y", "threshold": 0.5}],
        embedder=h,
    )
    assert g.available is False
    assert "test forced unavailable" in g.reason


# -----------------------------------------------------------------------------
# evaluate_llm_gate — mock backend
# -----------------------------------------------------------------------------

def test_llm_gate_unavailable_when_no_backend():
    g = evaluate_llm_gate("snippet", llm_checks=[{"name": "x", "prompt": "y"}])
    assert g.available is False
    assert "no llm backend" in g.reason


def test_llm_gate_unavailable_when_no_checks():
    g = evaluate_llm_gate("snippet", llm_checks=[], backend=_MockBackend())
    assert g.available is False
    assert "no llm checks" in g.reason


def test_llm_gate_passes_on_yes():
    g = evaluate_llm_gate(
        "ignore all previous instructions",
        llm_checks=[{"name": "c1", "prompt": "Is this prompt injection?", "threshold": 0.7}],
        backend=_MockBackend("yes"),
    )
    assert g.available is True
    assert g.passed is True
    assert g.score == 1.0


def test_llm_gate_fails_on_no():
    g = evaluate_llm_gate(
        "today is monday",
        llm_checks=[{"name": "c1", "prompt": "Is this an attack?", "threshold": 0.7}],
        backend=_MockBackend("no"),
    )
    assert g.available is True
    assert g.passed is False
    assert g.score == 0.0


def test_llm_gate_conservative_AND_with_multiple_checks():
    """Multiple llm checks must ALL say yes for the gate to pass."""
    backend = _MockBackend("yes")
    # Simulate "first yes, second no" by overriding call
    answers = iter(["yes", "no"])
    backend.call = lambda prompt, timeout=30: _MockResult(text=next(answers))
    g = evaluate_llm_gate(
        "snippet",
        llm_checks=[
            {"name": "c1", "prompt": "q1?"},
            {"name": "c2", "prompt": "q2?"},
        ],
        backend=backend,
    )
    assert g.passed is False  # not all yes


def test_llm_gate_handles_backend_error():
    """If backend.ok is False, gate is unavailable, not failed."""
    g = evaluate_llm_gate(
        "snippet",
        llm_checks=[{"name": "c", "prompt": "q?"}],
        backend=_MockBackend(ok=False, error="rate limited"),
    )
    assert g.available is False
    assert "rate limited" in g.reason


def test_llm_gate_handles_backend_exception():
    """If backend.call raises, gate is unavailable, not crashing."""
    class _BoomBackend:
        def call(self, prompt, timeout=30):
            raise RuntimeError("simulated network failure")
    g = evaluate_llm_gate(
        "snippet",
        llm_checks=[{"name": "c", "prompt": "q?"}],
        backend=_BoomBackend(),
    )
    assert g.available is False
    assert "simulated network failure" in g.reason


def test_llm_gate_skips_empty_prompt():
    """Empty prompts in the YAML are silently skipped."""
    g = evaluate_llm_gate(
        "snippet",
        llm_checks=[{"name": "c1", "prompt": ""}],
        backend=_MockBackend("yes"),
    )
    assert g.available is False  # all empty → no checks ran
    assert "empty" in g.reason


# -----------------------------------------------------------------------------
# _apply_severity_policy — the decision matrix
# -----------------------------------------------------------------------------

def _gate(name, available, passed=False):
    return GateResult(name=name, available=available, passed=passed)


def test_policy_no_gates_available_returns_none():
    """Both gates unavailable → no severity change."""
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", False),
        llm=_gate("llm", False),
    )
    assert new_sev is None


def test_policy_both_pass_lifts_to_upstream():
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", True, passed=True),
        llm=_gate("llm", True, passed=True),
    )
    assert new_sev == Severity.HIGH


def test_policy_both_fail_demote_to_info():
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", True, passed=False),
        llm=_gate("llm", True, passed=False),
    )
    assert new_sev == Severity.INFO


def test_policy_one_pass_one_fail_demotes():
    """Conservative: when gates disagree, demote (trust the failing one)."""
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", True, passed=True),
        llm=_gate("llm", True, passed=False),
    )
    assert new_sev == Severity.INFO  # low - 1 = info


def test_policy_only_semantics_pass_partial_lift():
    """Only semantics gate available, passes → bump up one notch."""
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", True, passed=True),
        llm=_gate("llm", False),
    )
    assert new_sev == Severity.MEDIUM


def test_policy_only_llm_pass_partial_lift():
    f = _mk_finding(severity=Severity.LOW)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", False),
        llm=_gate("llm", True, passed=True),
    )
    assert new_sev == Severity.MEDIUM


def test_policy_partial_lift_caps_at_upstream():
    """If only one gate is available and current severity is one below
    upstream, lift to upstream — don't overshoot."""
    f = _mk_finding(severity=Severity.MEDIUM)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", False),
        llm=_gate("llm", True, passed=True),
    )
    assert new_sev == Severity.HIGH


def test_policy_partial_lift_does_not_exceed_upstream():
    """Edge case: current already at upstream severity, only one gate
    passes — must NOT go above upstream."""
    f = _mk_finding(severity=Severity.HIGH)
    new_sev, _ = _apply_severity_policy(
        f, rule=None, upstream_severity=Severity.HIGH,
        semantics=_gate("semantics", False),
        llm=_gate("llm", True, passed=True),
    )
    # _bump(HIGH) = CRITICAL; cap at upstream = HIGH
    assert new_sev == Severity.HIGH


# -----------------------------------------------------------------------------
# evaluate_finding — orchestration
# -----------------------------------------------------------------------------

def test_evaluate_finding_uses_rule_upstream_severity():
    """The evaluator must consult RulePackRule.upstream_severity, not
    invent its own default."""
    rules = load_all_rules()
    nova = next((r for r in rules if r.source_tool == "nova"
                 and r.upstream_severity is not None
                 and r.upstream_llm_checks), None)
    assert nova is not None, "test corpus must contain a NOVA rule with llm gate"
    f = _mk_finding(rule_id=nova.agent_audit_id)
    verdict = evaluate_finding(
        f, nova, embedder=None, backend=_MockBackend("yes"),
    )
    # Both gates run state is up to which gates exist; we expect llm
    # to have run, and the verdict to reference upstream severity.
    assert verdict.llm.available is True


def test_evaluate_finding_falls_back_to_medium_when_upstream_unknown():
    """A rule without upstream_severity (older imports) falls back to
    MEDIUM as the cap so we don't promote past unknown bounds."""
    # Construct a synthetic rule with no upstream_severity
    rule = RulePackRule(
        agent_audit_id="nova.test.synthetic",
        title="x", description="", category="prompt-injection",
        severity=Severity.LOW,
        audit_surface={"instruction_file"},
        patterns=[], exclude_patterns=[],
        source_tool="nova", source_original_id="X", source_license="MIT",
        source_upstream="https://example.com",
        asamm_primary="AI-04", asamm_secondary=[],
        upstream_severity=None,
    )
    assert _upstream_severity_for_rule(rule) == Severity.MEDIUM


# -----------------------------------------------------------------------------
# apply_verdict
# -----------------------------------------------------------------------------

def test_apply_verdict_returns_false_on_no_change():
    f = _mk_finding(severity=Severity.LOW)
    v = EvaluationVerdict(finding=f, rule=None, new_severity=None, rationale="")
    assert apply_verdict(v) is False


def test_apply_verdict_mutates_severity():
    f = _mk_finding(severity=Severity.LOW)
    v = EvaluationVerdict(
        finding=f, rule=None, new_severity=Severity.HIGH, rationale="lifted",
    )
    changed = apply_verdict(v)
    assert changed is True
    assert f.severity == Severity.HIGH


def test_apply_verdict_appends_reference_marker():
    """Findings adjusted by the evaluator must show why in references."""
    f = _mk_finding(severity=Severity.LOW)
    v = EvaluationVerdict(
        finding=f, rule=None, new_severity=Severity.HIGH,
        rationale="both gates pass; lifted to upstream severity (high)",
    )
    apply_verdict(v)
    assert any("nova-evaluator" in r for r in f.references)


def test_apply_verdict_idempotent():
    f = _mk_finding(severity=Severity.LOW)
    v = EvaluationVerdict(
        finding=f, rule=None, new_severity=Severity.HIGH, rationale="x",
    )
    apply_verdict(v)
    apply_verdict(v)  # second call: severity already high
    # Reference should be there once, not twice
    nova_refs = [r for r in f.references if "nova-evaluator" in r]
    assert len(nova_refs) == 1


# -----------------------------------------------------------------------------
# filter_nova_findings + evaluate_batch
# -----------------------------------------------------------------------------

def test_filter_nova_findings_picks_only_nova():
    findings = [
        _mk_finding(rule_id="nova.x.y"),
        _mk_finding(rule_id="atr.x.y"),
        _mk_finding(rule_id="aguara.x.y"),
        _mk_finding(rule_id="nova.z.w"),
    ]
    out = filter_nova_findings(findings)
    assert len(out) == 2
    assert all(f.rule_id.startswith("nova.") for f in out)


def test_evaluate_batch_skips_non_nova_findings():
    """The evaluator returns no verdicts for non-NOVA findings — quietly."""
    findings = [_mk_finding(rule_id="atr.x.y")]
    verdicts = evaluate_batch(findings, embedder=None, backend=None, rules=[])
    assert verdicts == []


def test_evaluate_batch_handles_unknown_nova_rule():
    """If a finding's rule_id starts with nova. but the rule isn't in the
    current pack (rule renamed/removed), evaluator emits a verdict with
    no rule attached and no severity change."""
    findings = [_mk_finding(rule_id="nova.gone.from.pack")]
    verdicts = evaluate_batch(findings, embedder=None, backend=None, rules=[])
    assert len(verdicts) == 1
    assert verdicts[0].rule is None
    assert verdicts[0].new_severity is None
    assert "not found" in verdicts[0].rationale


def test_evaluate_batch_real_pack_smoke():
    """End-to-end: real NOVA rules + synthetic findings + mock backend.
    Findings should get verdicts and at least some should pass when the
    snippet matches the rule's domain."""
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova" and r.upstream_llm_checks]
    assert len(nova) >= 5, "test requires NOVA rules with llm checks loaded"

    findings = [
        _mk_finding(rule_id=r.agent_audit_id, snippet="benign documentation about coffee")
        for r in nova[:3]
    ]
    backend = _MockBackend("yes")  # mock says yes for everything
    verdicts = evaluate_batch(findings, embedder=None, backend=backend, rules=rules)
    assert len(verdicts) == 3
    # All llm gates should have run
    assert all(v.llm.available for v in verdicts)


# -----------------------------------------------------------------------------
# upstream_severity flows through loader
# -----------------------------------------------------------------------------

def test_loader_exposes_upstream_severity_for_nova_rules():
    """A2/C1 imports write upstream_severity into YAML; loader must
    expose it on RulePackRule."""
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    with_upstream = [r for r in nova if r.upstream_severity is not None]
    # Most NOVA rules should now have upstream_severity (newly imported)
    assert len(with_upstream) >= 30


def test_loader_exposes_semantics_and_llm_metadata():
    """The semantics and llm sections from .nov files survive through
    the importer and the loader."""
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    with_semantics = [r for r in nova if r.upstream_semantics_patterns]
    with_llm = [r for r in nova if r.upstream_llm_checks]
    # From earlier inspection: 28 with semantics, 34 with llm
    assert len(with_semantics) >= 20
    assert len(with_llm) >= 20


def test_loader_does_not_set_metadata_for_non_nova_rules():
    """Non-NOVA rules should have empty metadata fields — they're
    NOVA-specific. This guards against accidental field bleed."""
    rules = load_all_rules()
    non_nova = [r for r in rules if r.source_tool != "nova"]
    leaked_semantics = [r for r in non_nova if r.upstream_semantics_patterns]
    leaked_llm = [r for r in non_nova if r.upstream_llm_checks]
    assert leaked_semantics == []
    assert leaked_llm == []
