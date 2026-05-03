# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for tools/atlas_validate.py — Rules Expansion Roadmap item B3."""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.tools.atlas_validate import (  # noqa: E402
    AtlasReference,
    AtlasTechnique,
    ValidationIssue,
    _names_match,
    collect_references,
    load_atlas,
    main,
    render_json,
    render_text,
    validate,
)


# -----------------------------------------------------------------------------
# Fixtures
# -----------------------------------------------------------------------------

def _make_atlas_yaml(techniques: list) -> str:
    """Build a minimal ATLAS.yaml-shaped string from a list of (id, name, **kwargs)."""
    techs_yaml = ""
    for entry in techniques:
        tid, name = entry[0], entry[1]
        extra = entry[2] if len(entry) > 2 else {}
        techs_yaml += f"      - id: {tid}\n        name: {name}\n        object-type: technique\n"
        if extra.get("subtechnique-of"):
            techs_yaml += f"        subtechnique-of: {extra['subtechnique-of']}\n"
        if extra.get("deprecated"):
            techs_yaml += f"        deprecated: true\n"
        if extra.get("revoked"):
            techs_yaml += f"        revoked: true\n"
    return textwrap.dedent("""\
        id: ATLAS
        name: Adversarial Threat Landscape for AI Systems
        version: 99.0.0-test
        matrices:
          - id: ATLAS
            name: ATLAS Matrix
            techniques:
        """) + techs_yaml


@pytest.fixture
def fake_atlas(tmp_path):
    yaml_path = tmp_path / "ATLAS.yaml"
    yaml_path.write_text(_make_atlas_yaml([
        ("AML.T0001", "Real Technique"),
        ("AML.T0002", "Renamed Technique"),
        ("AML.T0003", "Deprecated Technique", {"deprecated": True}),
        ("AML.T0004", "Revoked Technique", {"revoked": True}),
        ("AML.T0001.000", "A Subtech", {"subtechnique-of": "AML.T0001"}),
    ]))
    return yaml_path


# -----------------------------------------------------------------------------
# load_atlas
# -----------------------------------------------------------------------------

def test_load_atlas_parses_techniques(fake_atlas):
    version, techs = load_atlas(fake_atlas)
    assert version == "99.0.0-test"
    assert "AML.T0001" in techs
    assert techs["AML.T0001"].name == "Real Technique"
    assert techs["AML.T0001"].is_subtechnique is False
    assert techs["AML.T0001.000"].is_subtechnique is True
    assert techs["AML.T0001.000"].parent_id == "AML.T0001"


def test_load_atlas_marks_deprecated_and_revoked(fake_atlas):
    _, techs = load_atlas(fake_atlas)
    assert techs["AML.T0003"].deprecated is True
    assert techs["AML.T0004"].revoked is True
    assert techs["AML.T0001"].deprecated is False


def test_load_atlas_missing_file_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_atlas(tmp_path / "does-not-exist.yaml")


def test_load_atlas_no_matrices_raises(tmp_path):
    bad = tmp_path / "ATLAS.yaml"
    bad.write_text("id: ATLAS\nversion: 0.0.0\nmatrices: []\n")
    with pytest.raises(ValueError):
        load_atlas(bad)


# -----------------------------------------------------------------------------
# _names_match
# -----------------------------------------------------------------------------

def test_names_match_ignores_case_and_whitespace():
    assert _names_match("LLM Prompt Injection", "LLM Prompt Injection")
    assert _names_match("llm prompt injection", "LLM PROMPT INJECTION")
    assert _names_match("LLM   Prompt  Injection", "LLM Prompt Injection")


def test_names_match_empty_cited_is_match():
    # ID-only references (no " - Name" portion) should not flag as mismatch
    assert _names_match("", "LLM Prompt Injection")


def test_names_match_actual_difference_fails():
    assert not _names_match("ML Supply Chain Compromise", "AI Supply Chain Compromise")


# -----------------------------------------------------------------------------
# validate — synthetic references
# -----------------------------------------------------------------------------

def _fake_techs():
    return {
        "AML.T0001": AtlasTechnique("AML.T0001", "Real Technique", False),
        "AML.T0003": AtlasTechnique("AML.T0003", "Deprecated Technique", False, deprecated=True),
        "AML.T0004": AtlasTechnique("AML.T0004", "Revoked Technique", False, revoked=True),
    }


def test_validate_ok_passthrough(tmp_path):
    refs = [AtlasReference("AML.T0001", "Real Technique", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert report.distinct_ids_total == 1
    assert report.distinct_ids_ok == 1
    assert report.issues == []
    assert not report.has_hard_errors


def test_validate_unknown_id_emits_unknown_issue(tmp_path):
    refs = [AtlasReference("AML.T9999", "Made Up", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert len(report.issues) == 1
    assert report.issues[0].kind == "unknown"
    assert report.has_hard_errors


def test_validate_deprecated_emits_deprecated_issue(tmp_path):
    refs = [AtlasReference("AML.T0003", "Deprecated Technique", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert len(report.issues) == 1
    assert report.issues[0].kind == "deprecated"
    assert report.has_hard_errors


def test_validate_revoked_emits_deprecated_issue(tmp_path):
    refs = [AtlasReference("AML.T0004", "Revoked Technique", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert report.issues[0].kind == "deprecated"


def test_validate_name_mismatch_emits_name_mismatch(tmp_path):
    refs = [AtlasReference("AML.T0001", "Old Name", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert len(report.issues) == 1
    assert report.issues[0].kind == "name_mismatch"
    assert report.issues[0].actual_name == "Real Technique"
    assert not report.has_hard_errors  # name drift is soft
    assert report.has_name_drift


def test_validate_id_only_reference_not_flagged_as_mismatch(tmp_path):
    """References without a cited name (e.g. 'AML.T0001' with empty name)
    should not produce name_mismatch — there's nothing to mismatch."""
    refs = [AtlasReference("AML.T0001", "", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "test")
    assert report.issues == []


def test_validate_groups_multiple_files_per_id(tmp_path):
    refs = [
        AtlasReference("AML.T9999", "Made Up", tmp_path / "a.yaml", "raw"),
        AtlasReference("AML.T9999", "Made Up", tmp_path / "b.yaml", "raw"),
        AtlasReference("AML.T9999", "Made Up", tmp_path / "c.yaml", "raw"),
    ]
    report = validate(refs, _fake_techs(), "test")
    assert len(report.issues) == 1
    assert len(report.issues[0].source_files) == 3


def test_validate_mixed_cited_names_for_same_id(tmp_path):
    """If two YAML files cite AML.T0001 with different names and at least
    one is wrong, we report the mismatch once."""
    refs = [
        AtlasReference("AML.T0001", "Real Technique", tmp_path / "a.yaml", "raw"),
        AtlasReference("AML.T0001", "Old Name", tmp_path / "b.yaml", "raw"),
    ]
    report = validate(refs, _fake_techs(), "test")
    assert len(report.issues) == 1
    assert report.issues[0].kind == "name_mismatch"
    assert "Real Technique" in report.issues[0].cited_name
    assert "Old Name" in report.issues[0].cited_name


# -----------------------------------------------------------------------------
# Output rendering
# -----------------------------------------------------------------------------

def test_render_text_no_issues(tmp_path):
    refs = [AtlasReference("AML.T0001", "Real Technique", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _fake_techs(), "1.0.0")
    out = render_text(report)
    assert "ATLAS version:        1.0.0" in out
    assert "Issues:               0" in out
    assert "UNKNOWN" not in out


def test_render_text_sections_for_issues(tmp_path):
    refs = [
        AtlasReference("AML.T9999", "Bad", tmp_path / "x.yaml", "raw"),
        AtlasReference("AML.T0003", "Deprecated Technique", tmp_path / "y.yaml", "raw"),
        AtlasReference("AML.T0001", "Wrong Name", tmp_path / "z.yaml", "raw"),
    ]
    report = validate(refs, _fake_techs(), "1.0.0")
    out = render_text(report)
    assert "UNKNOWN" in out
    assert "DEPRECATED" in out
    assert "NAME MISMATCH" in out


def test_render_json_round_trips(tmp_path):
    refs = [AtlasReference("AML.T9999", "Bad", tmp_path / "x.yaml", "raw")]
    report = validate(refs, _fake_techs(), "1.0.0")
    parsed = json.loads(render_json(report))
    assert parsed["atlas_version"] == "1.0.0"
    assert len(parsed["issues"]) == 1
    assert parsed["issues"][0]["technique_id"] == "AML.T9999"


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def test_main_returns_2_on_missing_atlas(tmp_path, capsys):
    rc = main(["--atlas", str(tmp_path / "nope.yaml"), "--quiet"])
    assert rc == 2


def test_main_returns_0_on_clean_run(fake_atlas, tmp_path, monkeypatch, capsys):
    """Clean run = no references in repo (we point references collection at
    an empty tree)."""
    # Trick collect_references into seeing an empty tree
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", tmp_path / "empty")
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "empty")
    rc = main(["--atlas", str(fake_atlas), "--quiet"])
    assert rc == 0


def test_main_returns_1_on_unknown_id(fake_atlas, tmp_path, monkeypatch):
    """If a rule cites an unknown ATLAS ID, default exit is 1 (hard error)."""
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        references:
          mitre_atlas:
            - AML.T9999 - Made Up Technique
    """))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")

    rc = main(["--atlas", str(fake_atlas), "--quiet"])
    assert rc == 1


def test_main_default_lenient_on_name_drift(fake_atlas, tmp_path, monkeypatch):
    """Default mode tolerates name drift (exit 0)."""
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        references:
          mitre_atlas:
            - AML.T0001 - Stale Name
    """))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")

    rc = main(["--atlas", str(fake_atlas), "--quiet"])
    assert rc == 0


def test_main_strict_fails_on_name_drift(fake_atlas, tmp_path, monkeypatch):
    """--strict promotes name drift to a hard error."""
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        references:
          mitre_atlas:
            - AML.T0001 - Stale Name
    """))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")

    rc = main(["--atlas", str(fake_atlas), "--strict", "--quiet"])
    assert rc == 1


# -----------------------------------------------------------------------------
# Reference collection
# -----------------------------------------------------------------------------

def test_collect_references_picks_up_yaml_refs(tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        references:
          mitre_atlas:
            - AML.T0051 - LLM Prompt Injection
            - AML.T0053 - AI Agent Tool Invocation
    """))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")

    refs = collect_references()
    ids = sorted({r.technique_id for r in refs})
    assert ids == ["AML.T0051", "AML.T0053"]


def test_collect_references_skips_index_files(tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    fake_packs.mkdir()
    # _index.yaml should be skipped even if it contains a mitre_atlas ref
    (fake_packs / "_index.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: ignored
        references:
          mitre_atlas:
            - AML.T9999 - Should Be Skipped
    """))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")

    refs = collect_references()
    assert refs == []


def test_collect_references_picks_up_python_refs(tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    fake_packs.mkdir()
    fake_detectors = tmp_path / "detectors"
    fake_detectors.mkdir()
    (fake_detectors / "sample.py").write_text(textwrap.dedent('''\
        refs = [
            "mitre_atlas:AML.T0051",
            "mitre_atlas:AML.T0054 - LLM Jailbreak",
        ]
    '''))
    import agent_audit.tools.atlas_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", fake_detectors)

    refs = collect_references()
    ids = sorted({r.technique_id for r in refs})
    assert ids == ["AML.T0051", "AML.T0054"]


# -----------------------------------------------------------------------------
# Real-data sanity check (uses vendored ATLAS snapshot)
# -----------------------------------------------------------------------------

def test_vendored_atlas_loads_and_has_known_techniques():
    """The vendored ATLAS snapshot must load cleanly and contain at least
    the techniques we currently rely on heavily (AML.T0051 is most-cited
    by far)."""
    from agent_audit.tools.atlas_validate import _VENDORED_ATLAS
    if not _VENDORED_ATLAS.exists():
        pytest.skip("Vendored ATLAS snapshot not present in this build.")
    version, techs = load_atlas(_VENDORED_ATLAS)
    assert version  # any non-empty
    assert "AML.T0051" in techs
    assert techs["AML.T0051"].name == "LLM Prompt Injection"
    # At least 100 techniques means we got a real distribution, not a stub
    assert len(techs) >= 100


def test_repo_has_no_unknown_or_deprecated_ids():
    """End-to-end check on the real repo: every cited mitre_atlas ID must
    map to a real, non-deprecated ATLAS technique. Name drift is allowed
    (handled by rule-pack maintenance) but ID-level drift must be zero."""
    from agent_audit.tools.atlas_validate import _VENDORED_ATLAS
    if not _VENDORED_ATLAS.exists():
        pytest.skip("Vendored ATLAS snapshot not present.")
    version, techs = load_atlas(_VENDORED_ATLAS)
    refs = collect_references()
    if not refs:
        pytest.skip("No mitre_atlas references in repo (unexpected).")
    report = validate(refs, techs, version)
    assert not report.has_hard_errors, (
        f"Found unknown/deprecated ATLAS IDs in rule references. "
        f"Issues: {[i.technique_id for i in report.issues if i.kind in ('unknown', 'deprecated')]}"
    )
