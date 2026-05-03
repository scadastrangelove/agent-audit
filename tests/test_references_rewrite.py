# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for the references_rewrite mechanism in rule_pack_overrides.yaml.

This is the upstream-drift-without-editing-upstream layer. Validates that
text replacements declared in rule_pack_overrides.yaml apply at rule load
time, without leaking into validators or other consumers that should see
the original text.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.rule_pack_loader import (  # noqa: E402
    _apply_reference_rewrites,
    _OVERRIDES,
    _OVERRIDES_REWRITES,
    _OVERRIDES_RULES,
    load_all_rules,
)


# -----------------------------------------------------------------------------
# Pure-function tests for _apply_reference_rewrites
# -----------------------------------------------------------------------------

def test_apply_rewrites_passthrough_when_no_match(monkeypatch):
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T9999 - X": "AML.T9999 - Y"}},
    )
    refs = {"mitre_atlas": ["AML.T0051 - LLM Prompt Injection"]}
    out = _apply_reference_rewrites(refs)
    # Unchanged: nothing matched
    assert out["mitre_atlas"] == ["AML.T0051 - LLM Prompt Injection"]


def test_apply_rewrites_substitutes_exact_match(monkeypatch):
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T0010 - ML Supply Chain Compromise":
                         "AML.T0010 - AI Supply Chain Compromise"}},
    )
    refs = {"mitre_atlas": ["AML.T0010 - ML Supply Chain Compromise"]}
    out = _apply_reference_rewrites(refs)
    assert out["mitre_atlas"] == ["AML.T0010 - AI Supply Chain Compromise"]


def test_apply_rewrites_preserves_other_fields(monkeypatch):
    """A rewrite for mitre_atlas must not touch owasp_llm or other fields."""
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T0010 - X": "AML.T0010 - Y"}},
    )
    refs = {
        "mitre_atlas": ["AML.T0010 - X"],
        "owasp_llm": ["LLM01:2025 - Prompt Injection"],
    }
    out = _apply_reference_rewrites(refs)
    assert out["mitre_atlas"] == ["AML.T0010 - Y"]
    assert out["owasp_llm"] == ["LLM01:2025 - Prompt Injection"]


def test_apply_rewrites_handles_missing_field(monkeypatch):
    """A rewrite scoped to a field that doesn't exist on this rule is a no-op."""
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T9999 - X": "AML.T9999 - Y"}},
    )
    refs = {"owasp_llm": ["LLM01"]}
    out = _apply_reference_rewrites(refs)
    assert out == {"owasp_llm": ["LLM01"]}


def test_apply_rewrites_handles_partial_list(monkeypatch):
    """When only some items in the list match, only those get rewritten."""
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T0010 - Old": "AML.T0010 - New"}},
    )
    refs = {"mitre_atlas": [
        "AML.T0010 - Old",
        "AML.T0051 - LLM Prompt Injection",  # untouched
    ]}
    out = _apply_reference_rewrites(refs)
    assert out["mitre_atlas"] == [
        "AML.T0010 - New",
        "AML.T0051 - LLM Prompt Injection",
    ]


def test_apply_rewrites_empty_overrides_returns_input(monkeypatch):
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {},
    )
    refs = {"mitre_atlas": ["AML.T0051 - LLM Prompt Injection"]}
    out = _apply_reference_rewrites(refs)
    assert out == refs


def test_apply_rewrites_does_not_mutate_input(monkeypatch):
    monkeypatch.setattr(
        "agent_audit.knowledge.rule_pack_loader._OVERRIDES_REWRITES",
        {"mitre_atlas": {"AML.T0010 - X": "AML.T0010 - Y"}},
    )
    original_refs = {"mitre_atlas": ["AML.T0010 - X"]}
    out = _apply_reference_rewrites(original_refs)
    # The output is rewritten, but the input dict is untouched
    assert original_refs["mitre_atlas"] == ["AML.T0010 - X"]
    assert out["mitre_atlas"] == ["AML.T0010 - Y"]


# -----------------------------------------------------------------------------
# Overrides-file structure
# -----------------------------------------------------------------------------

def test_overrides_file_has_both_sections():
    """Both `rules` and `references_rewrite` must load — confirms the YAML
    file structure is what _load_overrides() expects."""
    assert isinstance(_OVERRIDES, dict)
    assert "rules" in _OVERRIDES
    assert "references_rewrite" in _OVERRIDES


def test_overrides_severity_demotions_still_load():
    """Severity demotions from previous overrides must still be present after
    the section split. Catches accidental shape changes."""
    # We expect at least the three severity demotions documented in the file
    assert "aguara.external-download.runtime-url-controls-agent-behavior" in _OVERRIDES_RULES
    assert "atr.agent-manipulation.human-approval-fatigue-exploitation" in _OVERRIDES_RULES


def test_overrides_atlas_rewrites_present():
    """The 12 ATLAS name-drift rewrites we shipped in v0.16 must be loaded."""
    atlas_rewrites = _OVERRIDES_REWRITES.get("mitre_atlas", {})
    # Several distinctive ones
    assert "AML.T0010 - ML Supply Chain Compromise" in atlas_rewrites
    assert "AML.T0053 - LLM Plugin Compromise" in atlas_rewrites
    assert "AML.T0051 - Prompt Injection" in atlas_rewrites
    # Total at least 12 (we shipped exactly 12)
    assert len(atlas_rewrites) >= 12


# -----------------------------------------------------------------------------
# End-to-end: load_all_rules picks up the rewrites
# -----------------------------------------------------------------------------

def test_load_all_rules_applies_atlas_rewrites():
    """No rule should still cite a rewritten stale name. End-to-end check
    that the load-time rewrite pipeline catches every cite."""
    rules = load_all_rules()
    stale_strings = [
        "ML Supply Chain Compromise",
        "Backdoor ML Model",
        "Exfiltration via ML Inference API",
        "Full ML Model Access",
        "Spamming ML System with Chaff Data",
        "ML-Enabled Product or Service",
        "LLM Plugin Compromise",
        "LLM Meta Prompt Extraction",
    ]
    for r in rules:
        atlas_refs = r.references.get("mitre_atlas", [])
        for ref in atlas_refs:
            for stale in stale_strings:
                assert stale not in ref, (
                    f"Rule {r.agent_audit_id} still cites stale ATLAS name "
                    f"{stale!r} via {ref!r}. Either an override is missing or "
                    f"the rewrite didn't apply."
                )


def test_load_all_rules_substitutes_to_current_atlas_names():
    """At least one rule must end up citing the new ATLAS names — confirms
    the substitution actually happened, not just that stale names disappeared."""
    rules = load_all_rules()
    new_names_seen = set()
    fresh_strings = [
        "AI Supply Chain Compromise",
        "AI Agent Tool Invocation",
        "Manipulate AI Model",
        "AI Model Inference API Access",
    ]
    for r in rules:
        for ref in r.references.get("mitre_atlas", []):
            for fresh in fresh_strings:
                if fresh in ref:
                    new_names_seen.add(fresh)
    # We expect at least 3 of the 4 to appear in real rules
    assert len(new_names_seen) >= 3, (
        f"Only saw {new_names_seen} of the post-rewrite ATLAS names. "
        f"Rewrite pipeline may not be applying."
    )


# -----------------------------------------------------------------------------
# atlas-validate consumes rewrites
# -----------------------------------------------------------------------------

def test_atlas_validate_strict_passes_after_rewrites():
    """The whole point of shipping the 12 ATLAS rewrites: atlas-validate
    --strict against the real repo must now exit 0."""
    from agent_audit.tools.atlas_validate import (
        collect_references,
        load_atlas,
        validate,
        _VENDORED_ATLAS,
    )
    if not _VENDORED_ATLAS.exists():
        pytest.skip("Vendored ATLAS snapshot missing.")
    version, techs = load_atlas(_VENDORED_ATLAS)
    refs = collect_references()
    if not refs:
        pytest.skip("No mitre_atlas references in repo.")
    report = validate(refs, techs, version)
    # Hard errors (unknown / deprecated) must always be zero
    assert not report.has_hard_errors
    # Name drift must also be zero — that's what the rewrites achieve
    assert not report.has_name_drift, (
        f"ATLAS validator reports name drift after rewrites applied. "
        f"Issues: {[(i.technique_id, i.cited_name, i.actual_name) for i in report.issues if i.kind == 'name_mismatch']}"
    )
