# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Tests for NOVA importer + rule pack — Roadmap items A2/C1."""
from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest


ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.rule_pack_loader import load_all_rules  # noqa: E402
from agent_audit.tools.nova_import import (  # noqa: E402
    NovaRule,
    _condition_to_match_mode,
    _resolve_internal_category,
    _slugify,
    _split_rules,
    convert_rule,
    import_pack,
    parse_nov_file,
)


# -----------------------------------------------------------------------------
# _split_rules — find rule blocks in a .nov file
# -----------------------------------------------------------------------------

def test_split_single_rule():
    src = textwrap.dedent("""\
        rule MyRule
        {
            meta:
                description = "x"
            keywords:
                $a = "hello"
            condition:
                any of keywords.*
        }
    """)
    parts = _split_rules(src)
    assert len(parts) == 1
    assert "MyRule" in parts[0]
    assert "}" in parts[0]


def test_split_multiple_rules():
    src = textwrap.dedent("""\
        rule R1 {
            meta:
                description = "a"
            keywords:
                $x = "foo"
            condition:
                any of keywords.*
        }

        rule R2 {
            meta:
                description = "b"
            keywords:
                $y = "bar"
            condition:
                any of keywords.*
        }
    """)
    parts = _split_rules(src)
    assert len(parts) == 2
    assert "R1" in parts[0] and "R2" not in parts[0]
    assert "R2" in parts[1] and "R1" not in parts[1]


def test_split_handles_nested_braces_in_strings():
    """Brace counting must walk through string literals correctly."""
    src = 'rule R1 {\n    meta:\n        description = "uses { and } in text"\n    keywords:\n        $x = "y"\n    condition:\n        any of keywords.*\n}'
    parts = _split_rules(src)
    assert len(parts) == 1


# -----------------------------------------------------------------------------
# parse_nov_file — full file parsing
# -----------------------------------------------------------------------------

def test_parse_simple_rule(tmp_path):
    p = tmp_path / "test.nov"
    p.write_text(textwrap.dedent("""\
        rule MyRule
        {
            meta:
                description = "Test"
                author = "Tester"
                severity = "high"
                category = "prompt_manipulation/jailbreak"
            keywords:
                $a = "hello"
                $b = /world/i
            condition:
                any of keywords.*
        }
    """))
    rules = parse_nov_file(p)
    assert len(rules) == 1
    r = rules[0]
    assert r.name == "MyRule"
    assert r.meta["description"] == "Test"
    assert r.meta["author"] == "Tester"
    assert r.meta["severity"] == "high"
    # Keywords parsed correctly
    kw_names = [v[0] for v in r.keywords]
    assert "a" in kw_names
    assert "b" in kw_names
    # Kinds: a is string, b is regex
    by_name = {v[0]: v[1] for v in r.keywords}
    assert by_name["a"] == "string"
    assert by_name["b"] == "regex"


def test_parse_rule_with_semantics_and_llm(tmp_path):
    p = tmp_path / "test.nov"
    p.write_text(textwrap.dedent("""\
        rule R
        {
            meta:
                severity = "medium"
                category = "prompt_manipulation"
            keywords:
                $k = "kw"
            semantics:
                $s = "natural language pattern" (0.5)
            llm:
                $l = "Is this malicious?" (0.7)
            condition:
                keywords.$k or semantics.$s or llm.$l
        }
    """))
    rules = parse_nov_file(p)
    assert len(rules) == 1
    r = rules[0]
    assert len(r.semantics) == 1
    assert r.semantics[0][0] == "s"
    assert r.semantics[0][2] == 0.5
    assert len(r.llm) == 1
    assert r.llm[0][2] == 0.7


def test_parse_empty_file_returns_empty(tmp_path):
    p = tmp_path / "empty.nov"
    p.write_text("// just a comment\n")
    assert parse_nov_file(p) == []


# -----------------------------------------------------------------------------
# _slugify
# -----------------------------------------------------------------------------

def test_slugify_camelcase_to_kebab():
    assert _slugify("ObfuscationInjectionDetection") == "obfuscation-injection-detection"


def test_slugify_handles_acronym():
    """Acronyms stay together — fine for filenames."""
    out = _slugify("APIKeyLeak")
    # Either "a-p-i-key-leak" or "api-key-leak" — both safe for filenames
    assert "-" in out
    assert "_" not in out


def test_slugify_truncates_long():
    long = "X" + "Yyyy" * 30
    out = _slugify(long, max_len=40)
    assert len(out) <= 40


def test_slugify_falls_back_for_empty():
    assert _slugify("") == "rule"
    assert _slugify("---") == "rule"


# -----------------------------------------------------------------------------
# _resolve_internal_category
# -----------------------------------------------------------------------------

def test_resolve_known_category():
    assert _resolve_internal_category("prompt_manipulation/jailbreak") == "prompt-injection"
    assert _resolve_internal_category("suspicious_patterns/encoding") == "prompt-injection"
    assert _resolve_internal_category("abnormal_outputs/leak") == "context-exfiltration"


def test_resolve_unknown_category_default():
    """Unknown categories fall back to prompt-injection so MCP/ASI mapping
    still works rather than silently skipping the rule."""
    assert _resolve_internal_category("alien_thing/never_seen") == "prompt-injection"
    assert _resolve_internal_category("") == "prompt-injection"


# -----------------------------------------------------------------------------
# _condition_to_match_mode — the lossy mapping
# -----------------------------------------------------------------------------

def test_condition_any_of_keywords():
    mode, note = _condition_to_match_mode("any of keywords.*", n_keywords=3)
    assert mode == "any"


def test_condition_n_of_when_n_equals_total():
    """If upstream says '3 of keywords.*' and there are 3 keywords, that's
    semantically all-of. Use it."""
    mode, note = _condition_to_match_mode("3 of keywords.*", n_keywords=3)
    assert mode == "all"


def test_condition_n_of_when_n_less_than_total():
    """If upstream says '2 of 5', we can't enforce that with our matcher.
    Approximate as any-of and document the loss in the note."""
    mode, note = _condition_to_match_mode("2 of keywords.*", n_keywords=5)
    assert mode == "any"
    assert "approximat" in note.lower()


def test_condition_mixed_with_llm_keeps_keyword_side():
    """`(any of keywords.*) and (any of llm.*)` — we drop the llm side
    and keep the keyword conjunct."""
    mode, note = _condition_to_match_mode(
        "(any of keywords.*) and (any of llm.*)", n_keywords=3,
    )
    assert mode == "any"


def test_condition_explicit_keyword_ref():
    mode, note = _condition_to_match_mode("keywords.$base64", n_keywords=1)
    assert mode == "any"


def test_condition_unrecognized_falls_back_to_any():
    mode, note = _condition_to_match_mode(
        "very weird (custom expression)", n_keywords=2,
    )
    assert mode == "any"
    assert "unrecognized" in note.lower()


# -----------------------------------------------------------------------------
# convert_rule — single rule conversion
# -----------------------------------------------------------------------------

def _mk_nova(
    name="TestRule",
    severity="high",
    category="prompt_manipulation/jailbreak",
    keywords=None,
    condition="any of keywords.*",
):
    return NovaRule(
        name=name,
        meta={"description": "Test desc", "severity": severity,
              "category": category, "uuid": "abc-123",
              "author": "Tester"},
        keywords=keywords if keywords is not None else [("a", "string", "hello")],
        condition=condition,
    )


def test_convert_minimal_rule():
    rule = _mk_nova()
    out, reason = convert_rule(rule, "abc123def456")
    assert reason == ""
    assert out["agent_audit_id"] == "nova.prompt-injection.test-rule"
    assert out["category"] == "prompt-injection"
    assert out["asamm"]["primary"] == "AI-04"


def test_convert_demotes_severity_to_low():
    """Critical NOVA rule must come out at LOW because we don't have the
    semantics/llm evaluator."""
    rule = _mk_nova(severity="critical")
    out, _ = convert_rule(rule, "sha")
    assert out["severity_default"] == "low"
    note = out["upstream_severity_demotion_note"].lower()
    assert "floored" in note or "demoted" in note
    assert "low" in note


def test_convert_static_surfaces_only():
    """v0.17 NOVA: no session_* surfaces — keyword-only signal is too
    noisy for forensic mode without the full evaluator."""
    rule = _mk_nova()
    out, _ = convert_rule(rule, "sha")
    surfaces = out["audit_surface"]
    assert "session_user_input" not in surfaces
    assert "session_agent_output" not in surfaces
    assert "instruction_file" in surfaces


def test_convert_preserves_semantics_metadata():
    """NOVA semantics/llm sections are preserved as upstream_* metadata
    fields so a future evaluator can use them."""
    rule = NovaRule(
        name="X",
        meta={"description": "x", "severity": "medium",
              "category": "prompt_manipulation"},
        keywords=[("k", "string", "kw")],
        semantics=[("s", "prose pattern", 0.5)],
        llm=[("l", "Is this bad?", 0.7)],
        condition="any of keywords.*",
    )
    out, _ = convert_rule(rule, "sha")
    assert "upstream_semantics_patterns" in out
    assert out["upstream_semantics_patterns"][0]["prose"] == "prose pattern"
    assert "upstream_llm_checks" in out
    assert out["upstream_llm_checks"][0]["threshold"] == 0.7


def test_convert_preserves_uuid_and_author():
    rule = _mk_nova()
    out, _ = convert_rule(rule, "sha")
    assert out["external_source"]["upstream_uuid"] == "abc-123"
    assert out["external_source"]["upstream_author"] == "Tester"


def test_convert_skips_rules_without_keywords():
    """A NOVA rule with only semantics/llm has nothing for our matcher."""
    rule = NovaRule(
        name="OnlySemantic",
        meta={"description": "x", "severity": "high"},
        keywords=[],
        semantics=[("s", "prose", 0.5)],
        condition="any of semantics.*",
    )
    out, reason = convert_rule(rule, "sha")
    assert out is None
    assert "no-keywords" in reason


def test_convert_string_keyword_becomes_substring_regex():
    """String literals are escaped and made case-insensitive substring patterns."""
    rule = _mk_nova(keywords=[("a", "string", "Suspicious Phrase")])
    out, _ = convert_rule(rule, "sha")
    pat = out["patterns"][0]
    # Escaped form so 'Phrase' isn't accidentally a regex char
    assert "Suspicious" in pat["value"]
    assert "Phrase" in pat["value"]
    assert pat["value"].startswith("(?i)")


def test_convert_regex_keyword_passes_through():
    rule = _mk_nova(keywords=[("a", "regex", r"\bAKIA[A-Z0-9]{16}\b")])
    out, _ = convert_rule(rule, "sha")
    assert out["patterns"][0]["value"] == r"\bAKIA[A-Z0-9]{16}\b"


# -----------------------------------------------------------------------------
# import_pack — end-to-end
# -----------------------------------------------------------------------------

@pytest.fixture
def tiny_nov_corpus(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "test.nov").write_text(textwrap.dedent("""\
        rule R1
        {
            meta:
                description = "Detects something"
                severity = "high"
                category = "prompt_manipulation/jailbreak"
            keywords:
                $a = "ignore all previous"
            condition:
                any of keywords.*
        }

        rule R2NoKeywords
        {
            meta:
                description = "Should be skipped"
                severity = "high"
                category = "prompt_manipulation"
            llm:
                $check = "Is this bad?" (0.7)
            condition:
                any of llm.*
        }
    """))
    return src


def test_import_pack_writes_files(tiny_nov_corpus, tmp_path):
    dest = tmp_path / "dest"
    counts = import_pack(tiny_nov_corpus, dest, "abc123", dry_run=False)
    assert counts["__total__"] == 1   # R2 skipped (no keywords)
    assert counts["__skipped__"] == 1
    # File exists in expected category
    files = list((dest / "prompt-injection").glob("*.yaml"))
    assert len(files) == 1


def test_import_pack_dry_run(tiny_nov_corpus, tmp_path):
    dest = tmp_path / "dest"
    counts = import_pack(tiny_nov_corpus, dest, "abc123", dry_run=True)
    assert counts["__total__"] == 1
    assert not dest.exists()


def test_import_pack_aborts_on_no_files(tmp_path):
    src = tmp_path / "empty"
    src.mkdir()
    with pytest.raises(ValueError, match="No \\.nov"):
        import_pack(src, tmp_path / "dest", "abc", dry_run=True)


def test_import_pack_aborts_on_missing_dir(tmp_path):
    with pytest.raises(FileNotFoundError):
        import_pack(tmp_path / "nope", tmp_path / "dest", "abc", dry_run=True)


# -----------------------------------------------------------------------------
# Real-data sanity (vendored NOVA pack)
# -----------------------------------------------------------------------------

def test_nova_pack_loaded():
    """Vendored NOVA pack should appear in load_all_rules."""
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    assert len(nova) >= 30, f"Expected ≥30 NOVA rules; got {len(nova)}"


def test_nova_rules_all_low_severity():
    """v0.17 ships NOVA at LOW severity — see severity demotion in importer."""
    from agent_audit.rules import Severity
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    high_or_above = [r for r in nova if r.severity.order >= Severity.MEDIUM.order]
    assert not high_or_above, (
        f"NOVA rules with non-low severity: {[r.agent_audit_id for r in high_or_above]}. "
        f"NOVA must be LOW until M3 evaluator lands."
    )


def test_nova_rules_have_static_surfaces_only():
    """No NOVA rule should declare a session_* surface in v0.17."""
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    for r in nova:
        session_surfaces = [s for s in r.audit_surface if s.startswith("session_")]
        assert not session_surfaces, (
            f"NOVA rule {r.agent_audit_id} declares session surfaces "
            f"{session_surfaces} — these must wait for M3."
        )


def test_nova_rules_have_owasp_mappings():
    rules = load_all_rules()
    nova = [r for r in rules if r.source_tool == "nova"]
    no_mcp = [r for r in nova if "owasp_mcp" not in r.references]
    no_asi = [r for r in nova if "owasp_agentic" not in r.references]
    assert not no_mcp, f"{len(no_mcp)} NOVA rules missing owasp_mcp"
    assert not no_asi, f"{len(no_asi)} NOVA rules missing owasp_agentic"


def test_pack_count_now_5():
    """v0.17 brings the pack count to 5: atr, aguara, cisco-promptguard,
    gitleaks, nova."""
    rules = load_all_rules()
    tools = {r.source_tool for r in rules}
    assert "nova" in tools
    assert tools >= {"atr", "aguara", "cisco-promptguard", "gitleaks", "nova"}
