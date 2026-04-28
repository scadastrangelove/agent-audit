"""Aegis sensitive path rules — 70 patterns across 8 categories.

Source: github.com/antropos17/Aegis (MIT License, Copyright (c) 2026 AEGIS
Contributors). Bundled verbatim in aegis_rules/ subdirectory.

Categories (with rule counts, as of import):
  ai-config (35):     Claude, Cursor, Copilot, Codeium, Continue, Tabnine,
                      Aider, OpenClaw, Supermaven, JetBrains AI, Codex, Goose,
                      Warp, Gemini, ShellGPT, Mentat, Tabby, MetaGPT, Ollama,
                      Jan, LM Studio, GPT4All, Zed, and more.
  secrets (8):        .env, passwords, credentials, API tokens, keys,
                      .git-credentials.
  ssh (6):            ~/.ssh/, id_rsa, id_ed25519, id_ecdsa, known_hosts,
                      authorized_keys.
  cloud (3):          ~/.aws/, ~/.azure/, ~/.gcloud/.
  browser (9):        Chrome/Firefox/Edge login data, cookies, web data.
  devtools (4):       ~/.npmrc, ~/.pypirc, ~/.docker/config.json, ~/.kube/.
  crypto (1):         ~/.gnupg/.
  certificates (4):   *.pem, *.key, *.pfx, *.p12.

These patterns describe which filesystem paths are considered SENSITIVE.
An agent reading such a path is a high-severity signal on its own — and,
combined with a subsequent outbound network call, forms a credential-exfil
chain.

Aegis applies these rules at the syscall/file-watch layer (realtime).
agent-audit applies them in forensic mode — when we see a Read tool call
in a session log, we check the target path against these patterns.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

try:  # py 3.11+
    import tomllib  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover
    tomllib = None  # type: ignore[assignment]

# Lightweight YAML parser — we only need the rules subset, no general YAML.
# But since Aegis YAML uses anchors/quotes/complex patterns, use a minimal
# scanner instead of adding PyYAML as a dependency. The format is very
# regular so we can parse it line-by-line.


_RULES_DIR = Path(__file__).parent / "aegis_rules"

_CATEGORIES = [
    "ai-config",
    "secrets",
    "ssh",
    "cloud",
    "browser",
    "devtools",
    "crypto",
    "certificates",
]


@dataclass(frozen=True)
class PathRule:
    """A single path detection rule from Aegis."""
    id: str
    name: str
    pattern: str           # raw regex as published
    compiled: re.Pattern   # compiled regex
    reason: str
    category: str
    risk: str              # "critical" | "high" | "medium" | "low"


_CACHE: Optional[List[PathRule]] = None


def _unescape_yaml_string(s: str) -> str:
    """Unescape a YAML double-quoted string body.

    Aegis rule patterns are stored as YAML double-quoted strings where
    each literal backslash in the regex is written as \\\\. In YAML
    double-quoted strings, \\\\ means one backslash. Our minimal parser
    reads the raw line, so we need to apply YAML escape rules ourselves
    for the quoted value.

    Handles the escapes actually used in Aegis files: \\\\, \\/, \\".
    """
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "\\":
                out.append("\\")
                i += 2
                continue
            if nxt == "/":
                out.append("/")
                i += 2
                continue
            if nxt == '"':
                out.append('"')
                i += 2
                continue
            if nxt == "n":
                out.append("\n")
                i += 2
                continue
            if nxt == "t":
                out.append("\t")
                i += 2
                continue
            # Unknown escape — keep as-is
            out.append(s[i])
            i += 1
        else:
            out.append(s[i])
            i += 1
    return "".join(out)


def _parse_yaml_rules(text: str, category_hint: str) -> List[PathRule]:
    """Minimal YAML parser for Aegis rule files.

    We don't parse general YAML. We parse the specific structure used by
    Aegis: top-level `rules:` list, each item with keys id, name, pattern,
    reason, category, risk, enabled.
    """
    rules: List[PathRule] = []
    lines = text.splitlines()
    i = 0
    current: Dict[str, str] = {}
    in_rules_block = False

    def flush():
        if not current:
            return
        if current.get("enabled", "true").strip().lower() == "false":
            current.clear()
            return
        pattern = current.get("pattern", "")
        if not pattern:
            current.clear()
            return
        try:
            compiled = re.compile(pattern)
        except re.error:
            current.clear()
            return
        rules.append(PathRule(
            id=current.get("id", ""),
            name=current.get("name", ""),
            pattern=pattern,
            compiled=compiled,
            reason=current.get("reason", ""),
            category=current.get("category", category_hint),
            risk=current.get("risk", "high").strip().lower(),
        ))
        current.clear()

    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if stripped == "rules:":
            in_rules_block = True
        elif in_rules_block:
            if stripped.startswith("- id:"):
                flush()
                current["id"] = stripped.split(":", 1)[1].strip().strip('"')
            elif ":" in stripped and not stripped.startswith("#"):
                key, _, val = stripped.lstrip("- ").partition(":")
                key = key.strip()
                val = val.strip()
                # Strip outer quotes AND unescape YAML content
                if val.startswith('"') and val.endswith('"'):
                    val = _unescape_yaml_string(val[1:-1])
                else:
                    val = val.strip('"')
                if key in ("id", "name", "pattern", "reason", "category", "risk", "enabled"):
                    current[key] = val
        i += 1
    flush()
    return rules


def _load() -> List[PathRule]:
    """Load all rule files, cached."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE
    all_rules: List[PathRule] = []
    for cat in _CATEGORIES:
        path = _RULES_DIR / f"{cat}.yaml"
        if not path.exists():
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        all_rules.extend(_parse_yaml_rules(text, cat))
    _CACHE = all_rules
    return _CACHE


def all_rules() -> List[PathRule]:
    """All loaded path rules (across all categories)."""
    return _load()


def rules_by_category(category: str) -> List[PathRule]:
    """Filter rules by category."""
    return [r for r in all_rules() if r.category == category]


@dataclass(frozen=True)
class PathMatch:
    """A path that matched one or more Aegis rules."""
    path: str
    rules: tuple  # tuple of PathRule
    top_category: str
    top_risk: str


def classify_path(path: str) -> Optional[PathMatch]:
    """Classify a filesystem path against all Aegis rules.

    Returns PathMatch if at least one rule matches, else None.

    The path is tested as-is — caller is responsible for normalising home
    directory tokens etc. Typically you pass absolute or home-relative
    paths that came out of a session log.
    """
    matches: List[PathRule] = []
    for rule in all_rules():
        if rule.compiled.search(path):
            matches.append(rule)
    if not matches:
        return None
    # Top category = most-restrictive category among matches
    # Order: ssh > cloud > certificates > crypto > secrets > devtools > ai-config > browser
    cat_priority = {
        "ssh": 8, "cloud": 7, "certificates": 6, "crypto": 5,
        "secrets": 4, "devtools": 3, "ai-config": 2, "browser": 1,
    }
    top = max(matches, key=lambda r: cat_priority.get(r.category, 0))
    risk_priority = {"critical": 4, "high": 3, "medium": 2, "low": 1}
    top_risk_rule = max(matches, key=lambda r: risk_priority.get(r.risk, 0))
    return PathMatch(
        path=path,
        rules=tuple(matches),
        top_category=top.category,
        top_risk=top_risk_rule.risk,
    )


def is_sensitive_path(path: str) -> bool:
    """Quick boolean check — is this path in any Aegis category?"""
    return classify_path(path) is not None


def rule_count_by_category() -> Dict[str, int]:
    """Diagnostic: how many rules did we load per category."""
    counts: Dict[str, int] = {}
    for r in all_rules():
        counts[r.category] = counts.get(r.category, 0) + 1
    return counts
