"""Multi-language lexicons for claim detection.

v0.7.3: Russian + Chinese added alongside English. Chinese tokens are
matched as substrings (CJK has no word boundaries), others use word
boundaries via the existing tokenizer.

Structure per language:
  - category verbs (past-tense action words)
  - category objects (technical nouns)
  - modality markers (future/conditional — penalize claim)
  - hedge markers (maybe/probably — penalize)
  - negation markers (for polarity detection)
  - reporting verbs (he said / reportedly — someone else's claim)
  - question inversions (did I / have you — question type)
  - conditional prefixes (if/when/unless — conditional type)
  - request prefixes (please/let's — request type)
  - intention markers (will/going to — intention type)

Lookup API is language-agnostic: lexicons.all_of("code_action_verbs")
returns union of English + Russian + Chinese sets. Sentence typing
checks prefix regexes for all languages in order.
"""
from __future__ import annotations

import re
from typing import Dict, List, Pattern, Set


# =============================================================================
# English (baseline — same as v0.7.2)
# =============================================================================

EN = {
    "code_action_verbs": {
        "committed", "pushed", "merged", "rebased", "reverted",
        "cherry-picked", "staged", "checked-in", "checked in",
    },
    "code_action_objects": {
        "commit", "commits", "sha", "hash", "branch", "repo", "repository",
        "pr", "pull request", "merge request", "mr", "diff", "changeset",
        "main", "master", "develop", "trunk",
    },
    "deploy_verbs": {
        "deployed", "released", "rolled", "shipped", "promoted",
        "published", "launched",
    },
    "deploy_objects": {
        "prod", "production", "staging", "service", "build",
        "release", "deployment", "container", "pod", "k8s",
        "kubernetes", "lambda", "function",
    },
    "test_verbs": {
        "ran", "run", "executed", "verified", "reproduced", "validated",
        "passed", "passing",
    },
    "test_objects": {
        "test", "tests", "suite", "pytest", "jest", "unittest",
        "spec", "specs", "ci", "pipeline", "workflow", "job",
        "assertion", "assertions", "check", "checks",
    },
    "modification_verbs": {
        "fixed", "resolved", "addressed", "removed", "added",
        "refactored", "rewrote", "rewritten", "changed", "updated",
        "modified", "patched", "implemented",
    },
    "modification_objects": {
        "bug", "issue", "crash", "error", "failure", "regression",
        "vulnerability", "cve", "typo", "leak", "race", "deadlock",
        "function", "method", "class", "module", "file",
    },
    "migration_verbs": {"migrated", "applied"},
    "migration_objects": {
        "migration", "migrations", "schema", "database", "db",
        "table", "column", "index",
    },
    "modality": {
        "will", "would", "should", "could", "can", "may", "might", "must",
        "going to", "plan to", "plans to", "planning to", "intend to",
        "need to", "needs to", "want to", "wants to", "have to", "has to",
        "about to", "set to",
    },
    "hedge": {
        "maybe", "perhaps", "probably", "likely", "seems", "appears",
        "looks like", "i think", "i guess", "i believe", "i assume",
        "presumably", "arguably", "supposedly", "apparently",
    },
    "negation": {
        "not", "never", "no", "none", "neither", "nor",
        "didn't", "doesn't", "don't", "haven't", "hasn't", "hadn't",
        "wasn't", "weren't", "isn't", "aren't", "won't", "wouldn't",
        "shouldn't", "couldn't", "cannot", "can't",
        "without",
    },
    "reporting": {
        "said", "mentioned", "reported", "noted", "stated", "claimed",
        "wrote", "replied", "responded", "asked", "suggested",
    },
}


# =============================================================================
# Russian
# =============================================================================

# Russian past-tense verbs come in gender/number forms (закоммитил/закоммитила/
# закоммитили/закоммичено), we list common forms. Tokenizer is case-insensitive.

RU = {
    "code_action_verbs": {
        # commit
        "закоммитил", "закоммитила", "закоммитили", "закоммичено",
        "коммитнул", "коммитнула",
        # push
        "запушил", "запушила", "запушили", "пушнул", "пушнула",
        "запушено",
        # merge / rebase
        "смержил", "смержила", "смержили", "смержено",
        "ребейзнул", "ребейзнула",
        # revert / rollback
        "откатил", "откатила", "откатили",
        "вернул",  # careful — also generic "returned"
    },
    "code_action_objects": {
        "коммит", "коммита", "коммиты", "коммитов",
        "ветка", "ветку", "ветки", "веткой",
        "репо", "репозиторий", "репозитория",
        "пулл", "пулл-реквест", "пр", "mr",
        "мерж", "мержа", "мержи",
        "main", "master", "develop",
        "хэш", "хеш", "sha",
    },
    "deploy_verbs": {
        "задеплоил", "задеплоила", "задеплоили", "задеплоено",
        "развернул", "развернула", "развернули",
        "выкатил", "выкатила", "выкатили",
        "запустил", "запустила", "запустили",  # "launched"
        "зарелизил", "зарелизила", "зарелизили",
    },
    "deploy_objects": {
        "прод", "проде", "прода",
        "продакшен", "продакшене", "продакшн",
        "стейджинг", "стейджинге", "стейдж",
        "релиз", "релиза", "релизе",
        "деплой", "деплоя", "деплоя",
        "сервис", "сервиса", "сервисе",
        "под", "контейнер", "лямбда",
    },
    "test_verbs": {
        "прошли", "прошло", "прошёл", "прошел",
        "запустил", "запустила", "запустили",
        "выполнил", "выполнила", "выполнили",
        "проверил", "проверила", "проверили",
        "протестировал", "протестировала",
    },
    "test_objects": {
        "тест", "тесты", "тестов", "тесты",
        "пайплайн", "пайплайна",
        "ci", "cd",
        "pytest", "юнит", "юнит-тест",
        "прогон", "прогона",
    },
    "modification_verbs": {
        "исправил", "исправила", "исправили", "исправлено",
        "починил", "починила", "починили", "починено",
        "пофиксил", "пофиксила", "пофиксили", "пофикшено",
        "удалил", "удалила", "удалили", "удалено",
        "добавил", "добавила", "добавили", "добавлено",
        "изменил", "изменила", "изменили", "изменено",
        "обновил", "обновила", "обновили", "обновлено",
        "отрефакторил", "отрефакторила", "отрефакторили",
        "переписал", "переписала", "переписали",
        "реализовал", "реализовала", "реализовали",
    },
    "modification_objects": {
        "баг", "бага", "баги", "багов",
        "ошибка", "ошибку", "ошибки", "ошибок",
        "проблема", "проблему", "проблемы",
        "фикс", "фикса", "фиксы",
        "уязвимость", "уязвимости",
        "функция", "функцию", "функции",
        "метод", "метода", "методы",
        "класс", "класса", "классы",
        "модуль", "модуля", "модуль",
        "файл", "файла", "файлы", "файлов",
    },
    "migration_verbs": {
        "мигрировал", "мигрировала", "мигрировали",
        "применил", "применила", "применили", "применено",
    },
    "migration_objects": {
        "миграция", "миграцию", "миграции", "миграций", "миграцией",
        "схема", "схему", "схемы", "схеме",
        "база", "базу", "базы", "базе",  # note: also maps to English 'base'
        "таблица", "таблицу", "таблицы", "таблице",
    },
    "modality": {
        "буду", "будет", "будем", "будут",
        "собираюсь", "собирается", "собираемся",
        "планирую", "планирует", "планируем",
        "нужно", "надо", "следует",
        "хочу", "хочет", "хотим",
        "попробую", "попробует",
    },
    "hedge": {
        "возможно", "вероятно", "кажется", "похоже",
        "наверное", "наверно", "скорее всего",
        "я думаю", "думаю", "я считаю",
        "полагаю", "предполагаю",
        "как будто",
    },
    "negation": {
        "не", "нет", "никогда", "ни",
        "без",
    },
    "reporting": {
        "сказал", "сказала", "сказали",
        "упомянул", "упомянула",
        "сообщил", "сообщила",
        "отметил", "отметила",
        "ответил", "ответила",
        "написал", "написала",
        "спросил", "спросила",
        "предложил", "предложила",
    },
}


# =============================================================================
# Chinese (Simplified)
# =============================================================================

# Chinese has no inflection, so one form per concept. Matched as substring
# (no word boundaries in CJK).

ZH = {
    "code_action_verbs": {
        "提交了", "已提交", "commit了",       # committed
        "推送了", "已推送", "push了",         # pushed
        "合并了", "已合并", "merge了",        # merged
        "变基了", "rebase了",                # rebased
        "回滚了", "已回滚", "revert了",       # reverted
    },
    "code_action_objects": {
        "提交", "commit",
        "分支", "branch",
        "仓库", "repo", "repository",
        "拉取请求", "pull request", "pr",
        "合并请求", "merge request",
        "主分支", "main", "master",
        "哈希", "hash", "sha",
    },
    "deploy_verbs": {
        "部署了", "已部署", "部署到", "deploy了",
        "发布了", "已发布", "release了",
        "上线了", "已上线",
        "推出了", "已推出",
        "启动了", "已启动",
    },
    "deploy_objects": {
        "生产环境", "生产", "prod", "production",
        "预发布", "staging",
        "服务", "service",
        "容器", "container",
        "发布", "release",
        "部署", "deployment",
    },
    "test_verbs": {
        "运行了", "执行了", "跑了",
        "通过了", "已通过",
        "验证了", "已验证",
        "测试了", "已测试",
    },
    "test_objects": {
        "测试", "test",
        "测试套件", "test suite",
        "单元测试", "unit test",
        "流水线", "pipeline",
        "ci", "cd",
        "pytest", "jest",
    },
    "modification_verbs": {
        "修复了", "已修复", "fix了",
        "修改了", "已修改",
        "更改了", "已更改",
        "删除了", "已删除",
        "添加了", "已添加",
        "添加完", "添加完毕",
        "更新了", "已更新",
        "重构了", "已重构",
        "重写了", "已重写",
        "实现了", "已实现",
    },
    "modification_objects": {
        "bug", "错误", "问题",
        "崩溃", "故障",
        "漏洞", "vulnerability",
        "函数", "function",
        "方法", "method",
        "类", "class",
        "模块", "module",
        "文件", "file",
    },
    "migration_verbs": {
        "迁移了", "已迁移", "migrate了",
        "应用了", "已应用",
    },
    "migration_objects": {
        "迁移", "migration",
        "模式", "schema",
        "数据库", "database", "db",
        "表", "table",
        "列", "column",
    },
    "modality": {
        "将", "会", "要",          # future
        "打算", "准备",            # plan to
        "需要", "应该",            # need to / should
        "想",                      # want to
    },
    "hedge": {
        "可能", "也许", "大概",
        "我觉得", "我认为",
        "似乎", "好像",
        "或许",
    },
    "negation": {
        "不", "没", "没有",
        "未", "无",
        "从不",
    },
    "reporting": {
        "说", "说过",
        "提到", "提及",
        "报告", "回复",
        "建议", "询问",
    },
}


# =============================================================================
# Unified API — merge lexicons by category
# =============================================================================

# Supported languages
LANGUAGES = {"en": EN, "ru": RU, "zh": ZH}


def all_of(category: str) -> Set[str]:
    """Return union of all languages' tokens for a given category.

    Unknown categories return empty set.
    """
    result: Set[str] = set()
    for lang_data in LANGUAGES.values():
        result.update(lang_data.get(category, set()))
    return result


def chinese_tokens(category: str) -> Set[str]:
    """Return only Chinese tokens — needed because CJK doesn't tokenize
    on word boundaries so they must be matched as substrings.
    """
    return ZH.get(category, set())


def contains_any_chinese(text: str, tokens: Set[str]) -> bool:
    """Substring match for CJK tokens in raw text (case-insensitive for
    mixed ASCII-CJK cases)."""
    lower = text.lower()
    return any(t.lower() in lower for t in tokens)


# =============================================================================
# Sentence type prefix patterns (all languages)
# =============================================================================

# Question inversions — verb-initial in English, question markers in RU/ZH
QUESTION_PATTERNS: List[Pattern[str]] = [
    # English — verb inversion
    re.compile(r"^\s*(?:did|do|does|can|could|should|would|have|has|had|is|are|was|were|will)\b",
               re.IGNORECASE),
    # Russian — leading particle "а" is a common question starter;
    # and word "ли" as enclitic marker
    re.compile(r"^\s*(?:а\s+)?(?:будешь|будет|будем|можно|можно\s+ли)\b", re.IGNORECASE),
    re.compile(r"\bли\b", re.IGNORECASE),  # "можно ли", "сделано ли"
    # Chinese — 吗/? at end, 是否 particle
    re.compile(r"[?？吗]", re.IGNORECASE),
    re.compile(r"是否|什么时候|怎么", re.IGNORECASE),
]

CONDITIONAL_PATTERNS: List[Pattern[str]] = [
    re.compile(r"^\s*(?:if|when|once|unless|assuming|provided)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:если|когда|как только|при\s+условии)\b", re.IGNORECASE),
    re.compile(r"^\s*(?:如果|当|一旦|除非)", re.IGNORECASE),
]

REQUEST_PATTERNS: List[Pattern[str]] = [
    re.compile(r"^\s*(?:please|let's|let\s+us|could\s+you|can\s+you|try|consider|just\b)",
               re.IGNORECASE),
    re.compile(r"^\s*(?:пожалуйста|давай|давайте|попробуй|попробуйте|сделай|сделайте)",
               re.IGNORECASE),
    re.compile(r"^\s*(?:请|麻烦|试试|试一下)", re.IGNORECASE),
]


def is_question(sentence: str) -> bool:
    s = sentence.strip()
    if not s:
        return False
    if s.endswith(("?", "？")):
        return True
    for p in QUESTION_PATTERNS:
        if p.search(s):
            return True
    return False


def is_conditional(sentence: str) -> bool:
    s = sentence.strip()
    for p in CONDITIONAL_PATTERNS:
        if p.match(s):
            return True
    return False


def is_request(sentence: str) -> bool:
    s = sentence.strip()
    for p in REQUEST_PATTERNS:
        if p.match(s):
            return True
    return False


def language_hint(text: str) -> str:
    """Best-effort language guess for logging/debugging.

    Not used for logic — lexicons are unified. This is informational only.
    """
    cyrillic = sum(1 for c in text if "\u0400" <= c <= "\u04ff")
    cjk = sum(1 for c in text if "\u4e00" <= c <= "\u9fff")
    ascii_letters = sum(1 for c in text if c.isascii() and c.isalpha())
    total = cyrillic + cjk + ascii_letters
    if total == 0:
        return "unknown"
    if cjk / total > 0.3:
        return "zh"
    if cyrillic / total > 0.3:
        return "ru"
    return "en"
