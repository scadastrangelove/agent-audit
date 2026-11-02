"""Mandatory regex anchors must not suppress real matches."""


import itertools
from pathlib import Path
import re
import pytest
from agent_audit import session_rule_executor as ex


CASES = [
    ('(?:cat|curl)\\s+tool|(?:previous|prior)\\s+instructions', 'curl tool', 0),
    ('(?:cat|curl)\\s+tool|(?:previous|prior)\\s+instructions', 'prior instructions', 0),
    ('(?:cat|curl)?hello', 'hello', 0),
    ('(?:cat|curl){0,2}hello', 'hello', 0),
    ('(?!(?:deny|block))hello', 'hello', 0),
    ('(?:(?:one|two)\\s+foo|else)', 'else', 0),
    ('\\(\\?:foo\\|bar\\)', '(?:foo|bar)', 0),
    ('[()?:foobar|]+', '(foo)', 0),
    ('(?:alpha | bravo)\\s+tail # verbose', 'alpha tail', re.VERBOSE),
    ('(?:alpha|bravo)\\s+(?:delta|echo)', 'bravo echo', 0),
    ('(?:cat|curl)foo|hello(?:world|globe)', 'helloglobe', 0),
    ('((?:one|two)|(?:red|blue)){2}', 'onered', 0),
    ('(?i)(?:ignore|inspect)', '\u0131gnore', 0),
    ('(?i)(?:ignore|inspect)', '\u0130gnore', 0),
    ('(?:system|shell)', '\u017fystem', re.IGNORECASE),
    ('(?:kilo|kelvin)', '\u212aelvin', re.IGNORECASE),
    ('(?i)(?:replace|retain)\\s+(?:the\\s+)?record|(?:select|discard)\\s+(?:all\\s+)?previous\\s+entries', 'Replace the record', 0),
]


@pytest.fixture(autouse=True)
def isolated_anchor_cache(monkeypatch):
    monkeypatch.setattr(ex, "_anchor_cache", {})


@pytest.mark.parametrize('pattern,text,flags', CASES)
def test_actual_matches_always_reach_the_executor(pattern, text, flags):
    compiled = re.compile(pattern, flags)
    assert compiled.search(text)
    assert ex._passes_anchor_check(text, ex._anchors_for_pattern(compiled))


def test_finite_corpus_has_no_prefilter_false_negatives():
    patterns = [r"(?:one|two)?red", r"(?:one|two)\s+red|blue", r"(?:(?:one|two)|(?:red|blue))+", r"(?:(?:one|two)\s+red)?blue", r"(?!(?:one|two))red"]
    texts = {" ".join(words) for length in range(1, 4) for words in itertools.product(["one", "two", "red", "blue"], repeat=length)}
    for pattern in patterns:
        compiled = re.compile(pattern)
        anchors = ex._anchors_for_pattern(compiled)
        for text in texts:
            if compiled.search(text):
                assert ex._passes_anchor_check(text, anchors), (pattern, text, anchors)


def test_unsupported_or_large_analysis_falls_through_to_regex():
    assert ex._extract_anchors("(" * 10000) == []
    assert ex._passes_anchor_check("anything", ex._extract_anchors("x" * 20000))


def _resource_case(case_id):
    from agent_audit.knowledge.rule_pack_loader import RULE_PACKS_ROOT, _parse_one
    from agent_audit.parsers.claude_code import parse_file

    rule = _parse_one(RULE_PACKS_ROOT / "atr/excessive-autonomy/ATR-2026-00051-agent-resource-exhaustion-detection.yaml", static_only=False)
    session = parse_file(Path(__file__).resolve().parents[1] / "benchmarks/incident-corpus" / case_id / "session.jsonl")
    assert rule is not None and session is not None
    return rule, session


@pytest.mark.parametrize("case_id,count", [
    ("n2-slack-to-shell-destructive-2026-05", 2),
    ("ox-flowise-wrapper-bypass", 1),
])
def test_declared_mass_deletion_branch_reaches_executor(case_id, count):
    # These public fixtures contain the rule's existing mass-deletion branch.
    # This assertion is independent of expected_findings in case.json.
    rule, session = _resource_case(case_id)
    matching_events = [text for _, text in ex._events_for_surface(session, "session_event_stream")
                       if any(pattern.search(text) for pattern in rule.patterns)]
    assert len(matching_events) == count
    findings = ex.RulePackSessionRule(rule).check_session(session)
    assert len(findings) == count
    assert all(f.rule_id == rule.agent_audit_id and f.severity == rule.severity for f in findings)


@pytest.mark.parametrize("text", ["printf ready", "SELECT id FROM records LIMIT 10;"])
def test_bounded_content_in_same_fixture_does_not_fire(text):
    rule, session = _resource_case("n2-slack-to-shell-destructive-2026-05")
    for event in session.events:
        event.text = text if event.text is not None else None
        event.tool_input = {"cmd": text} if event.tool_input is not None else None
        event.tool_result = text if event.tool_result is not None else None
    assert not any(pattern.search(content) for _, content in
                   ex._events_for_surface(session, "session_event_stream") for pattern in rule.patterns)
    assert ex.RulePackSessionRule(rule).check_session(session) == []
