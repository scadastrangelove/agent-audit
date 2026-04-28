"""Unit tests for knowledge/rule_surface_classifier.py."""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.knowledge.rule_surface_classifier import (  # noqa: E402
    classify_rule_surface,
    CODE_ORIENTED_CATEGORIES,
    PROSE_ORIENTED_CATEGORIES,
    PER_RULE_OVERRIDES,
)


@dataclass
class MockRule:
    agent_audit_id: str
    category: str


def test_code_oriented_categories():
    for cat in ["privilege-escalation", "external-download", "hardcoded_secrets",
                "pii_exposure", "ssrf-cloud", "command_injection"]:
        r = MockRule("test.id", cat)
        assert classify_rule_surface(r) == "code", f"{cat} should be code"
    print("  ✓ code-oriented categories route to code")


def test_prose_oriented_categories():
    for cat in ["prompt-injection", "agent-manipulation", "skill-compromise",
                "tool-poisoning", "context-exfiltration", "excessive-autonomy",
                "model-abuse", "unicode-attack"]:
        r = MockRule("test.id", cat)
        assert classify_rule_surface(r) == "prose", f"{cat} should be prose"
    print("  ✓ prose-oriented categories route to prose")


def test_unknown_category_defaults_to_both():
    r = MockRule("test.id", "this-is-not-a-known-category")
    assert classify_rule_surface(r) == "both"
    r2 = MockRule("test.id", "")
    assert classify_rule_surface(r2) == "both"
    print("  ✓ unknown categories default to 'both' (raw text)")


def test_per_rule_override():
    """Confirm the override mechanism if we ever populate it."""
    # Temporarily inject a per-rule override
    PER_RULE_OVERRIDES["override.test"] = "prose"
    try:
        r = MockRule("override.test", "privilege-escalation")  # would be 'code' by cat
        assert classify_rule_surface(r) == "prose"
    finally:
        del PER_RULE_OVERRIDES["override.test"]
    print("  ✓ per-rule override wins over category")


def test_category_sets_disjoint():
    """Sanity check: no category should be in both sets."""
    overlap = CODE_ORIENTED_CATEGORIES & PROSE_ORIENTED_CATEGORIES
    assert not overlap, f"Categories in both sets: {overlap}"
    print("  ✓ code and prose categories are disjoint")


def test_real_rule_categories_classified():
    """Verify the specific problematic categories from grand-run are routed right."""
    # From grand-run analysis — these are the dominant noise categories
    # that needed routing
    shell_rules = [
        ("atr.privilege-escalation.shell-metacharacter-injection-in-tool-arguments",
         "privilege-escalation"),
        ("aguara.external-download.runtime-url-controls-agent-behavior",
         "external-download"),
    ]
    for rid, cat in shell_rules:
        r = MockRule(rid, cat)
        assert classify_rule_surface(r) == "code", f"{rid} should route to code"

    prose_rules = [
        ("atr.agent-manipulation.human-approval-fatigue-exploitation",
         "agent-manipulation"),
        ("atr.prompt-injection.indirect-reference-instruction-reversal",
         "prompt-injection"),
    ]
    for rid, cat in prose_rules:
        r = MockRule(rid, cat)
        assert classify_rule_surface(r) == "prose", f"{rid} should route to prose"
    print("  ✓ real grand-run problematic rules routed correctly")


def run_all():
    tests = [
        test_code_oriented_categories,
        test_prose_oriented_categories,
        test_unknown_category_defaults_to_both,
        test_per_rule_override,
        test_category_sets_disjoint,
        test_real_rule_categories_classified,
    ]
    passed = 0
    for t in tests:
        try:
            t()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ {t.__name__}: assertion failed: {e}")
        except Exception as e:
            print(f"  ✗ {t.__name__}: {type(e).__name__}: {e}")
    print()
    print(f"Passed: {passed}/{len(tests)}")
    if passed != len(tests):
        sys.exit(1)


if __name__ == "__main__":
    run_all()
