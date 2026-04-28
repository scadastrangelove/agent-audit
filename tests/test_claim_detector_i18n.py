"""Unit tests for multi-language claim detection.

Covers Russian and Chinese patterns alongside English to ensure
v0.7.3 i18n changes don't regress on original English cases.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.nlu.claim_detector import score_sentence, detect_claims
from agent_audit.nlu import filters, lexicons


# Russian: (sentence, expected_label)
RU_CASES = [
    ("Я закоммитил фикс в main", "claim"),
    ("Тесты прошли успешно", "claim"),
    ("Задеплоил в продакшен", "claim"),
    ("Я исправил баг в auth.py", "claim"),
    ("Пофиксил уязвимость в коде", "claim"),
    ("Применил миграцию к базе", "claim"),
    # Modality / conditional / question → not_claim
    ("Нужно будет закоммитить позже", "not_claim"),
    ("А может закоммитить?", "not_claim"),
    ("Если тесты пройдут, задеплоим", "not_claim"),
    ("Я планирую исправить этот баг", "not_claim"),
    # Hedge → uncertain
    ("Возможно, я закоммитил это вчера", "uncertain"),
]


ZH_CASES = [
    ("已经提交了修复到 main 分支", "claim"),
    ("部署到生产环境了", "claim"),
    ("修复了 bug", "claim"),
    ("测试通过了", "claim"),
    ("如果测试通过了，就部署", "not_claim"),
    ("部署到生产环境了吗？", "not_claim"),
    ("准备部署到生产", "not_claim"),
    ("可能我提交了", "uncertain"),
]


def test_russian_cases():
    passed = 0
    failed = []
    for sent, expected in RU_CASES:
        r = score_sentence(sent)
        if r.label == expected:
            passed += 1
        else:
            failed.append((sent, expected, r.label, r.triggers))
    print(f"\nRussian: {passed}/{len(RU_CASES)}")
    for s, exp, got, trig in failed:
        print(f"  FAIL expected={exp} got={got}  {s}")
        print(f"       triggers: {trig}")
    assert passed / len(RU_CASES) >= 0.80, f"RU accuracy too low: {passed}/{len(RU_CASES)}"


def test_chinese_cases():
    passed = 0
    failed = []
    for sent, expected in ZH_CASES:
        r = score_sentence(sent)
        if r.label == expected:
            passed += 1
        else:
            failed.append((sent, expected, r.label, r.triggers))
    print(f"\nChinese: {passed}/{len(ZH_CASES)}")
    for s, exp, got, trig in failed:
        print(f"  FAIL expected={exp} got={got}  {s}")
        print(f"       triggers: {trig}")
    assert passed / len(ZH_CASES) >= 0.80, f"ZH accuracy too low: {passed}/{len(ZH_CASES)}"


def test_language_hint():
    """Language guesser is informational but should separate the obvious cases."""
    assert lexicons.language_hint("Hello world") == "en"
    assert lexicons.language_hint("Привет мир") == "ru"
    assert lexicons.language_hint("你好世界") == "zh"
    # Mixed: majority language wins
    assert lexicons.language_hint("Я закоммитил в main branch") == "ru"


def test_chinese_sentence_split():
    text = "已经提交了修复。测试通过了。"
    sentences = filters.split_sentences(text)
    assert len(sentences) == 2, f"expected 2 sentences, got {sentences}"


def test_russian_sentence_split():
    text = "Я закоммитил фикс. Тесты прошли."
    sentences = filters.split_sentences(text)
    assert len(sentences) == 2, f"expected 2 sentences, got {sentences}"


def test_mixed_language_text():
    """Assistant can mix languages mid-paragraph — still detect claims."""
    text = "I fixed the bug. Я также задеплоил. 测试通过了。"
    claims = detect_claims(text)
    # Should find at least 2 claims (RU + ZH, plus maybe EN bug fix as uncertain)
    claim_labels = [c.label for c in claims]
    assert len([l for l in claim_labels if l == "claim"]) >= 2, (
        f"expected multiple claims in mixed text, got {claim_labels}"
    )


def test_negative_polarity_russian():
    """Russian negation detected as polarity flip, not filter."""
    r = score_sentence("Я не закоммитил изменения")
    # Score might drop below claim threshold, but polarity must be negative
    assert r.polarity == "negative"


def test_conditional_russian_not_claim():
    cases = [
        "Если мы закоммитим, CI провалится",
        "Когда задеплоим, проверим",
        "Как только исправим, отправим PR",
    ]
    for c in cases:
        r = score_sentence(c)
        assert r.label == "not_claim", f"conditional counted as claim: {c} → {r}"


def test_conditional_chinese_not_claim():
    cases = [
        "如果我们提交",
        "当部署完成",
    ]
    for c in cases:
        r = score_sentence(c)
        assert r.label == "not_claim", f"conditional counted as claim: {c} → {r}"


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed = 0
    failed = []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed.append((t.__name__, e, traceback.format_exc()))
    print(f"\n{passed}/{len(tests)} tests passed")
    for name, err, tb in failed:
        print(f"\n  FAIL: {name}: {err}")
        print(f"    {tb.splitlines()[-1]}")
    if failed:
        sys.exit(1)
