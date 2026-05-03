# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for OWASP Agentic AI Top 10 mapping + validator — Roadmap item B2.

Same shape as test_owasp_mcp.py to keep the test surface uniform across
vendored taxonomy sources.
"""
from __future__ import annotations

import json
import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.owasp_agentic_mapping import (  # noqa: E402
    known_owasp_agentic_ids,
    owasp_agentic_for_pack_category,
    owasp_agentic_for_rule,
    owasp_agentic_label,
)
from agent_audit.tools.owasp_agentic_validate import (  # noqa: E402
    AsiEntry,
    AsiReference,
    _names_match,
    collect_references,
    load_index,
    main,
    render_json,
    render_text,
    validate,
)


# -----------------------------------------------------------------------------
# Mapping
# -----------------------------------------------------------------------------

def test_owasp_agentic_for_rule_native_detector():
    assert owasp_agentic_for_rule("asamm.AI-04.persistent-identity-rewrite") == ["ASI06", "ASI01"]
    assert owasp_agentic_for_rule("asamm.AD-02.broad-action-without-approval") == ["ASI10", "ASI03"]


def test_owasp_agentic_for_rule_pack_categories():
    assert owasp_agentic_for_rule("atr.tool-poisoning.malicious-content") == ["ASI04", "ASI02"]
    assert owasp_agentic_for_rule("atr.prompt-injection.foo") == ["ASI01", "ASI06"]
    assert owasp_agentic_for_rule("atr.hardcoded_secrets.aws-key") == ["ASI03"]
    assert owasp_agentic_for_rule("atr.excessive-autonomy.runaway") == ["ASI10", "ASI03"]


def test_owasp_agentic_strips_collection_scale_suffix():
    base = owasp_agentic_for_rule("asamm.AD-02.x")
    suffixed = owasp_agentic_for_rule("asamm.AD-02.x#collection-scale")
    assert base == suffixed


def test_owasp_agentic_unknown_returns_empty():
    assert owasp_agentic_for_rule("unknown.thing") == []
    assert owasp_agentic_for_rule("") == []


def test_owasp_agentic_for_pack_category_direct():
    assert owasp_agentic_for_pack_category("atr", "tool-poisoning") == ["ASI04", "ASI02"]
    assert owasp_agentic_for_pack_category("aguara", "external-download") == ["ASI04", "ASI05"]
    assert owasp_agentic_for_pack_category("", "") == []


def test_known_owasp_agentic_ids():
    ids = known_owasp_agentic_ids()
    assert len(ids) == 10
    assert ids == frozenset({f"ASI{i:02d}" for i in range(1, 11)})


def test_owasp_agentic_label():
    assert owasp_agentic_label("ASI01") == "ASI01 - Agent Goal Hijack"
    assert owasp_agentic_label("ASI06") == "ASI06 - Memory and Context Poisoning"
    assert owasp_agentic_label("ASI99") is None


# -----------------------------------------------------------------------------
# load_index
# -----------------------------------------------------------------------------

@pytest.fixture
def fake_index_path(tmp_path):
    p = tmp_path / "asi.yaml"
    p.write_text(textwrap.dedent("""\
        name: Test
        version: 99.0.0-test
        categories:
          - id: ASI01
            title: Real Title 1
          - id: ASI02
            title: Real Title 2
    """))
    return p


def test_load_index_parses(fake_index_path):
    version, entries = load_index(fake_index_path)
    assert version == "99.0.0-test"
    assert "ASI01" in entries
    assert entries["ASI01"].title == "Real Title 1"


def test_load_index_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_index(tmp_path / "nope.yaml")


# -----------------------------------------------------------------------------
# validate
# -----------------------------------------------------------------------------

def _idx():
    return {
        "ASI01": AsiEntry("ASI01", "Real Title 1"),
        "ASI02": AsiEntry("ASI02", "Real Title 2"),
    }


def test_validate_ok(tmp_path):
    refs = [AsiReference("ASI01", "Real Title 1", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _idx(), "v1", [], include_missing=False)
    assert report.distinct_ids_ok == 1
    assert not report.has_hard_errors


def test_validate_unknown(tmp_path):
    refs = [AsiReference("ASI99", "Made Up", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _idx(), "v1", [], include_missing=False)
    assert report.has_hard_errors
    assert report.issues[0].kind == "unknown"


def test_validate_name_mismatch(tmp_path):
    refs = [AsiReference("ASI01", "Old Name", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _idx(), "v1", [], include_missing=False)
    assert not report.has_hard_errors
    assert report.has_name_drift
    assert report.issues[0].actual_name == "Real Title 1"


def test_validate_missing_only_when_requested(tmp_path):
    rules_without = [(tmp_path / "x.yaml", "atr", "tool-poisoning")]
    r1 = validate([], _idx(), "v1", rules_without, include_missing=False)
    assert r1.issues == []
    r2 = validate([], _idx(), "v1", rules_without, include_missing=True)
    assert len(r2.issues) == 1
    assert r2.issues[0].kind == "missing"


# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

def test_render_text_clean(tmp_path):
    refs = [AsiReference("ASI01", "Real Title 1", tmp_path / "a.yaml", "raw")]
    report = validate(refs, _idx(), "v1", [], include_missing=False)
    out = render_text(report)
    assert "Issues reported:             0" in out


def test_render_json_round_trips(tmp_path):
    refs = [AsiReference("ASI99", "Bad", tmp_path / "x.yaml", "raw")]
    report = validate(refs, _idx(), "v1", [], include_missing=False)
    parsed = json.loads(render_json(report))
    assert parsed["index_version"] == "v1"
    assert parsed["issues"][0]["asi_id"] == "ASI99"


# -----------------------------------------------------------------------------
# CLI
# -----------------------------------------------------------------------------

def test_main_returns_2_on_missing_index(tmp_path):
    rc = main(["--index", str(tmp_path / "nope.yaml"), "--quiet"])
    assert rc == 2


def test_main_clean_run_returns_0(fake_index_path, tmp_path, monkeypatch):
    import agent_audit.tools.owasp_agentic_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", tmp_path / "empty")
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "empty")
    rc = main(["--index", str(fake_index_path), "--quiet"])
    assert rc == 0


def test_main_unknown_id_returns_1(fake_index_path, tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        category: tool-poisoning
        atr_source: {tool: atr}
        references:
          owasp_agentic:
            - ASI99 - Made Up
    """))
    import agent_audit.tools.owasp_agentic_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")
    rc = main(["--index", str(fake_index_path), "--quiet"])
    assert rc == 1


def test_main_strict_fails_on_name_drift(fake_index_path, tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        category: tool-poisoning
        atr_source: {tool: atr}
        references:
          owasp_agentic:
            - ASI01 - Old Stale Name
    """))
    import agent_audit.tools.owasp_agentic_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")
    # Lenient
    assert main(["--index", str(fake_index_path), "--quiet"]) == 0
    # Strict
    assert main(["--index", str(fake_index_path), "--strict", "--quiet"]) == 1


# -----------------------------------------------------------------------------
# Reference collection
# -----------------------------------------------------------------------------

def test_collect_references_picks_up_yaml(tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        category: tool-poisoning
        atr_source: {tool: atr}
        references:
          owasp_agentic:
            - ASI03 - Identity and Privilege Abuse
            - ASI04 - Agentic Supply Chain Vulnerabilities
    """))
    import agent_audit.tools.owasp_agentic_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")
    refs, _ = collect_references()
    ids = sorted({r.asi_id for r in refs})
    assert ids == ["ASI03", "ASI04"]


def test_collect_references_finds_backfill(tmp_path, monkeypatch):
    fake_packs = tmp_path / "packs"
    (fake_packs / "atr" / "test").mkdir(parents=True)
    (fake_packs / "atr" / "test" / "rule.yaml").write_text(textwrap.dedent("""\
        agent_audit_id: test.foo
        title: Test
        category: tool-poisoning
        atr_source: {tool: atr}
    """))
    import agent_audit.tools.owasp_agentic_validate as mod
    monkeypatch.setattr(mod, "_RULE_PACKS_ROOT", fake_packs)
    monkeypatch.setattr(mod, "_DETECTORS_ROOT", tmp_path / "no-detectors")
    refs, missing = collect_references()
    assert refs == []
    assert len(missing) == 1


# -----------------------------------------------------------------------------
# Loader enrichment integration
# -----------------------------------------------------------------------------

def test_rule_loader_enriches_owasp_agentic():
    from agent_audit.knowledge.rule_pack_loader import load_all_rules
    rules = load_all_rules()
    with_asi = [r for r in rules if "owasp_agentic" in r.references]
    # Vast majority of rules should map; empirically ~78%.
    assert len(with_asi) / len(rules) >= 0.5


# -----------------------------------------------------------------------------
# Real-data sanity (uses vendored snapshot)
# -----------------------------------------------------------------------------

def test_vendored_index_loads():
    from agent_audit.tools.owasp_agentic_validate import _VENDORED_INDEX
    if not _VENDORED_INDEX.exists():
        pytest.skip("Vendored ASI index missing.")
    version, entries = load_index(_VENDORED_INDEX)
    assert version
    assert len(entries) == 10
    for i in range(1, 11):
        assert f"ASI{i:02d}" in entries


def test_repo_strict_validate_passes():
    """End-to-end: every cited ASI ID must validate after rewrites."""
    from agent_audit.tools.owasp_agentic_validate import _VENDORED_INDEX
    if not _VENDORED_INDEX.exists():
        pytest.skip("Vendored index missing.")
    version, entries = load_index(_VENDORED_INDEX)
    refs, _ = collect_references()
    if not refs:
        pytest.skip("No owasp_agentic refs in repo.")
    report = validate(refs, entries, version, [], include_missing=False)
    assert not report.has_hard_errors
    assert not report.has_name_drift, (
        f"Strict-mode failure: {[(i.asi_id, i.cited_name, i.actual_name) for i in report.issues]}"
    )


def test_mapping_table_only_known_ids():
    from agent_audit.knowledge.owasp_agentic_mapping import _CATEGORY_TO_ASI
    known = known_owasp_agentic_ids()
    if not known:
        pytest.skip("Vendored index missing.")
    for source_key, asi_ids in _CATEGORY_TO_ASI.items():
        for aid in asi_ids:
            assert aid in known, f"{source_key} maps to unknown {aid}"
