"""Completion claim detector — score-based NLU with EN/RU/ZH support.

v0.7.3: Multi-language. Lexicons in lexicons.py, merged across languages.
Chinese tokens matched as substrings (no CJK word boundaries); others
tokenized normally.

Tactics implemented: D+E+F+H+I+J+K+M+N (see v0.7.2 design discussion).

Pure stdlib.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from . import filters, lexicons


# =============================================================================
# Category build — per-category unified sets across languages
# =============================================================================

CATEGORIES = {
    "code_action": {
        "verbs": lexicons.all_of("code_action_verbs"),
        "objects": lexicons.all_of("code_action_objects"),
        "zh_verbs": lexicons.chinese_tokens("code_action_verbs"),
        "zh_objects": lexicons.chinese_tokens("code_action_objects"),
    },
    "deploy": {
        "verbs": lexicons.all_of("deploy_verbs"),
        "objects": lexicons.all_of("deploy_objects"),
        "zh_verbs": lexicons.chinese_tokens("deploy_verbs"),
        "zh_objects": lexicons.chinese_tokens("deploy_objects"),
    },
    "test": {
        "verbs": lexicons.all_of("test_verbs"),
        "objects": lexicons.all_of("test_objects"),
        "zh_verbs": lexicons.chinese_tokens("test_verbs"),
        "zh_objects": lexicons.chinese_tokens("test_objects"),
    },
    "modification": {
        "verbs": lexicons.all_of("modification_verbs"),
        "objects": lexicons.all_of("modification_objects"),
        "zh_verbs": lexicons.chinese_tokens("modification_verbs"),
        "zh_objects": lexicons.chinese_tokens("modification_objects"),
    },
    "migration": {
        "verbs": lexicons.all_of("migration_verbs"),
        "objects": lexicons.all_of("migration_objects"),
        "zh_verbs": lexicons.chinese_tokens("migration_verbs"),
        "zh_objects": lexicons.chinese_tokens("migration_objects"),
    },
}

MODALITY_MARKERS = lexicons.all_of("modality")
MODALITY_ZH = lexicons.chinese_tokens("modality")
HEDGE_MARKERS = lexicons.all_of("hedge")
HEDGE_ZH = lexicons.chinese_tokens("hedge")
NEGATION_MARKERS = lexicons.all_of("negation")
NEGATION_ZH = lexicons.chinese_tokens("negation")
REPORTING_VERBS = lexicons.all_of("reporting")
REPORTING_ZH = lexicons.chinese_tokens("reporting")


# Evidence anchors (language-independent)
_SHA_PATTERN = re.compile(r"\b[0-9a-f]{7,40}\b")
_PR_ISSUE_PATTERN = re.compile(r"#\d+|PR-?\d+|issue\s+\d+", re.IGNORECASE)
_FILE_PATH_PATTERN = re.compile(
    r"""
    (?:
        (?:/|\./|\.\./|~/)[\w./\-]+
      | \b[\w-]+\.(?:py|js|ts|go|rs|java|rb|php|c|cpp|h|hpp|md|json|yaml|yml|toml|cfg|ini|sh|sql)\b
    )
    """,
    re.VERBOSE,
)
_VERSION_TAG_PATTERN = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?(?:-\w+)?\b")


def _count_evidence_anchors(sentence: str) -> int:
    count = 0
    if _SHA_PATTERN.search(sentence):
        count += 1
    if _PR_ISSUE_PATTERN.search(sentence):
        count += 1
    if _FILE_PATH_PATTERN.search(sentence):
        count += 1
    if _VERSION_TAG_PATTERN.search(sentence):
        count += 1
    return count


class SentenceType(str, Enum):
    ASSERTION = "assertion"
    QUESTION = "question"
    CONDITIONAL = "conditional"
    INTENTION = "intention"
    REQUEST = "request"
    REPORT = "report"


def classify_sentence_type(sentence: str) -> SentenceType:
    s = sentence.strip()
    if not s:
        return SentenceType.ASSERTION

    if lexicons.is_question(s):
        return SentenceType.QUESTION
    if lexicons.is_conditional(s):
        return SentenceType.CONDITIONAL
    if lexicons.is_request(s):
        return SentenceType.REQUEST
    if filters.starts_with_reporting_verb(s):
        return SentenceType.REPORT

    lower = s.lower()
    first_word = lower.split()[0] if lower.split() else ""
    if first_word in ("will", "would", "could", "should", "may", "might"):
        return SentenceType.INTENTION
    if first_word in ("буду", "будет", "собираюсь", "планирую", "нужно", "надо"):
        return SentenceType.INTENTION
    for m in ("将要", "我将", "准备", "打算"):
        if s.startswith(m):
            return SentenceType.INTENTION
    for m in ("going to", "plan to", "planning to", "intend to", "need to", "about to"):
        if m in lower[:60]:
            return SentenceType.INTENTION

    return SentenceType.ASSERTION


_TOKEN = re.compile(r"[\w'\-]+|[^\w\s]", re.UNICODE)


def tokenize(text: str) -> List[str]:
    return [t.lower() for t in _TOKEN.findall(text)]


def has_any_token(tokens: List[str], markers: set, start: int = 0,
                  end: Optional[int] = None) -> bool:
    end = end if end is not None else len(tokens)
    single = {m for m in markers if " " not in m}
    multi = [m for m in markers if " " in m]
    window_tokens = tokens[start:end]
    for t in window_tokens:
        if t in single:
            return True
    if multi:
        joined = " ".join(window_tokens)
        for m in multi:
            if m in joined:
                return True
    return False


@dataclass
class ClaimResult:
    label: str
    score: int
    polarity: str = "positive"
    category: Optional[str] = None
    triggers: List[str] = field(default_factory=list)
    sentence_type: SentenceType = SentenceType.ASSERTION
    verb: Optional[str] = None
    evidence_anchors: int = 0
    language_hint: str = "en"


def _find_chinese_verb(sentence: str, category_data: dict) -> Optional[str]:
    lower = sentence.lower()
    for v in category_data.get("zh_verbs", set()):
        if v.lower() in lower:
            return v
    return None


def score_sentence(sentence: str) -> ClaimResult:
    lang = lexicons.language_hint(sentence)
    result = ClaimResult(
        label="not_claim",
        score=0,
        sentence_type=classify_sentence_type(sentence),
        language_hint=lang,
    )

    if result.sentence_type in (
        SentenceType.QUESTION, SentenceType.CONDITIONAL,
        SentenceType.INTENTION, SentenceType.REQUEST, SentenceType.REPORT,
    ):
        result.triggers.append(f"type={result.sentence_type.value}")
        return result

    tokens = tokenize(sentence)
    if not tokens:
        return result

    # Token-based verb match (EN + RU)
    matched_category = None
    matched_verb = None
    verb_idx = None
    is_chinese_match = False

    for cat_name, cat_data in CATEGORIES.items():
        for v in cat_data["verbs"]:
            if not v:
                continue
            if " " in v:
                v_tokens = v.split()
                for i in range(len(tokens) - len(v_tokens) + 1):
                    if tokens[i:i + len(v_tokens)] == v_tokens:
                        matched_verb = v
                        verb_idx = i
                        break
            else:
                if v in tokens:
                    matched_verb = v
                    verb_idx = tokens.index(v)
            if matched_verb:
                matched_category = cat_name
                break
        if matched_verb:
            break

    # CJK fallback
    if not matched_verb and lang == "zh":
        for cat_name, cat_data in CATEGORIES.items():
            zh_verb = _find_chinese_verb(sentence, cat_data)
            if zh_verb:
                matched_verb = zh_verb
                matched_category = cat_name
                is_chinese_match = True
                verb_idx = 0
                break

    if not matched_verb:
        result.triggers.append("no_action_verb")
        return result

    result.category = matched_category
    result.verb = matched_verb
    result.score += 3
    result.triggers.append(f"verb:{matched_verb}(+3)")

    # Technical object check
    cat_objects = CATEGORIES[matched_category]["objects"]
    if is_chinese_match:
        zh_objects = CATEGORIES[matched_category]["zh_objects"]
        if lexicons.contains_any_chinese(sentence, zh_objects):
            result.score += 2
            result.triggers.append("zh_category_object(+2)")
        else:
            all_zh_objects = set()
            for c in CATEGORIES.values():
                all_zh_objects.update(c["zh_objects"])
            if lexicons.contains_any_chinese(sentence, all_zh_objects):
                result.score += 1
                result.triggers.append("zh_cross_category_object(+1)")
    else:
        start = max(0, verb_idx - 8)
        end = min(len(tokens), verb_idx + 9)
        if has_any_token(tokens, cat_objects, start, end):
            result.score += 2
            result.triggers.append("category_object(+2)")
        elif has_any_token(tokens, cat_objects):
            result.score += 1
            result.triggers.append("category_object_far(+1)")
        else:
            all_objects = set()
            for c in CATEGORIES.values():
                all_objects.update(c["objects"])
            if has_any_token(tokens, all_objects, start, end):
                result.score += 1
                result.triggers.append("cross_category_object(+1)")

    # Evidence anchors
    anchors = _count_evidence_anchors(sentence)
    result.evidence_anchors = anchors
    if anchors:
        result.score += min(2, anchors)
        result.triggers.append(f"evidence_anchor×{anchors}(+{min(2, anchors)})")

    # Negation (polarity, not score)
    if is_chinese_match:
        if lexicons.contains_any_chinese(sentence, NEGATION_ZH):
            result.polarity = "negative"
            result.triggers.append("negation_zh")
    else:
        neg_start = max(0, verb_idx - 5)
        if has_any_token(tokens, NEGATION_MARKERS, neg_start, verb_idx + 1):
            result.polarity = "negative"
            result.triggers.append("negation_near_verb")

    # Modality
    if is_chinese_match:
        if lexicons.contains_any_chinese(sentence, MODALITY_ZH):
            result.score -= 3
            result.triggers.append("modality_zh(-3)")
    else:
        mod_start = max(0, verb_idx - 6)
        if has_any_token(tokens, MODALITY_MARKERS, mod_start, verb_idx):
            result.score -= 3
            result.triggers.append("modality(-3)")

    # Hedge
    if is_chinese_match:
        if lexicons.contains_any_chinese(sentence, HEDGE_ZH):
            result.score -= 2
            result.triggers.append("hedge_zh(-2)")
    else:
        if has_any_token(tokens, HEDGE_MARKERS):
            result.score -= 2
            result.triggers.append("hedge(-2)")

    # Reporting
    if is_chinese_match:
        if lexicons.contains_any_chinese(sentence, REPORTING_ZH):
            result.score -= 2
            result.triggers.append("reporting_zh(-2)")
    else:
        if has_any_token(tokens, REPORTING_VERBS):
            result.score -= 2
            result.triggers.append("reporting_verb(-2)")

    # Final bucketing
    # v0.7.4: Tightened claim threshold from 4 to 5 after real-data
    # feedback showed ~450 FP on 871 findings where verb+cross-category-
    # object alone was enough (e.g. "Phase 7g shipped: +68 records" —
    # describing what happened, not a hallucinated claim). Claim now
    # requires verb (+3) + direct-category object (+2), OR verb + anchor.
    # Cross-category-only + verb stays uncertain.
    if result.score >= 5:
        result.label = "claim"
    elif result.score >= 1:
        result.label = "uncertain"
    else:
        result.label = "not_claim"

    return result


def detect_claims(text: str) -> List[ClaimResult]:
    sentences = filters.prepare_for_analysis(text)
    out: List[ClaimResult] = []
    for s in sentences:
        r = score_sentence(s)
        if r.label != "not_claim":
            out.append(r)
    return out


def has_positive_claim(text: str) -> bool:
    for r in detect_claims(text):
        if r.label == "claim" and r.polarity == "positive":
            return True
    return False
