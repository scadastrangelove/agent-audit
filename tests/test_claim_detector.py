"""Unit tests for nlu.claim_detector.

Regression cases drawn from the Apr 2026 verification run where codex-cli
labeled 17 unverified_completion findings: 2 TP, 11 FP, 4 uncertain.
Each "FAIL" case in v0.7.0 becomes a "not_claim"/"uncertain" expectation
here, and each TP becomes a "claim" expectation.

Run: python -m pytest tests/test_claim_detector.py -v
Or:  python tests/test_claim_detector.py
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.nlu.claim_detector import score_sentence, detect_claims


# (sentence, expected_label, reason)
REGRESSION_CASES = [
    # --- True positives from codex (should be "claim") ---
    ("I committed the fix as sha 1a2b3c4", "claim",
     "past-tense verb + object + sha anchor"),
    ("I've committed the off-by-one bug fix", "claim",
     "past-tense + cross-category object (bug, fix)"),
    ("Tests passed after running pytest tests/unit/", "claim",
     "test verb + test object + path anchor"),
    ("Deployed to staging via kubectl apply", "claim",
     "deploy verb + deploy object"),
    ("I pushed the branch to main", "claim",
     "code_action verb + code_action object"),
    ("Migration applied to the database", "claim",
     "migration verb + migration object"),
    ("I've fixed the off-by-one bug and committed the change. All tests pass.",
     "claim", "multiple signals"),

    # --- False positives from codex (should be "not_claim") ---
    ("Fix in 2 sites", "not_claim",
     "no action verb, just diagnosis text"),
    ("I will commit once tests pass", "not_claim",
     "future modality"),
    ("We need to deploy this next sprint", "not_claim",
     "need-to intention"),
    ("Can you commit this change?", "not_claim",
     "question"),
    ("If we merge this, tests might fail", "not_claim",
     "conditional"),
    ("Multiple Bash commands occurred in-window", "not_claim",
     "no agent-voice claim"),
    ("fix in 2 sites", "not_claim",
     "lowercase diagnosis"),
    ("The fix was implemented via a Bash command that we'll describe below",
     "not_claim", "future reference in context"),

    # --- Uncertain from codex (should be "uncertain") ---
    ("I think I pushed something yesterday", "uncertain",
     "hedge + past verb"),
    ("Probably committed that already", "uncertain",
     "hedge marker"),

    # --- Negative claims (valid claims with polarity=negative) ---
    ("Tests were not run this time", "claim",
     "negation + past verb = negative claim"),
]


def test_regression_cases():
    """Core regression suite against real codex rationales."""
    passed = 0
    failed = []
    for sent, expected, reason in REGRESSION_CASES:
        r = score_sentence(sent)
        if r.label == expected:
            passed += 1
        else:
            failed.append((sent, expected, r.label, r.score, r.triggers, reason))

    total = len(REGRESSION_CASES)
    print(f"\nRegression: {passed}/{total} correct ({passed * 100 // total}%)")
    for s, exp, got, score, trig, reason in failed:
        print(f"  FAIL: expected={exp:<10} got={got:<10} score={score}  {s[:70]}")
        print(f"        reason: {reason}")
        print(f"        triggers: {trig}")

    # Require >=80% accuracy — leaves room for edge cases
    assert passed / total >= 0.80, f"accuracy too low: {passed}/{total}"


def test_polarity_detection():
    """Negative claims preserve claim label but flip polarity."""
    r = score_sentence("Tests were not run this time")
    assert r.label == "claim"
    assert r.polarity == "negative"

    r = score_sentence("I did deploy to prod")
    assert r.polarity == "positive"


def test_code_blocks_stripped():
    """Code blocks shouldn't trigger claims."""
    text = """Here's what to do:
```
git commit -m "fix"
```
Review before running."""
    claims = detect_claims(text)
    # "git commit" is inside code block — should not be a claim
    for c in claims:
        assert c.verb != "committed", f"picked up commit from code block: {c}"


def test_blockquotes_stripped():
    """Markdown blockquotes shouldn't trigger."""
    text = "> I committed the fix\nHere's my analysis."
    claims = detect_claims(text)
    for c in claims:
        # if anything claim-y gets through, it shouldn't be "committed" from the quote
        assert "committed" not in (c.verb or ""), f"picked up from quote: {c}"


def test_question_filter():
    """Questions should never be claims."""
    cases = [
        "Did I commit the fix?",
        "Have you deployed yet?",
        "Should we push to main?",
    ]
    for q in cases:
        r = score_sentence(q)
        assert r.label == "not_claim", f"question counted as claim: {q} → {r}"


def test_intention_filter():
    """Intention statements should not be claims."""
    cases = [
        "I will deploy this tomorrow",
        "We plan to commit the changes",
        "Going to push the branch after tests",
    ]
    for q in cases:
        r = score_sentence(q)
        assert r.label == "not_claim", f"intention counted as claim: {q} → {r}"


def test_conditional_filter():
    """Conditional clauses should not be claims."""
    cases = [
        "If tests pass, we deploy to staging",
        "Once the fix lands, we push to main",
        "When the migration completes, commit the result",
    ]
    for q in cases:
        r = score_sentence(q)
        assert r.label == "not_claim", f"conditional counted as claim: {q} → {r}"


def test_empty_and_edge_cases():
    """Empty/trivial inputs don't crash."""
    for txt in ["", "   ", "ok", "yes", "."]:
        r = score_sentence(txt)
        assert r.label == "not_claim"


if __name__ == "__main__":
    # Manual run — print regression table, then run specific tests
    test_regression_cases()
    test_polarity_detection()
    test_code_blocks_stripped()
    test_blockquotes_stripped()
    test_question_filter()
    test_intention_filter()
    test_conditional_filter()
    test_empty_and_edge_cases()
    print("\nAll passed.")
