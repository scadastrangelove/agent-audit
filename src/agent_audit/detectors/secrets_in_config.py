"""AI-05 Secrets embedded in agent configuration files.

Motivated by SecOps audit F-2:
  > Credentials exposed in multiple locations: git history, disk, settings
  > files, archive transport.

Agent config files — CLAUDE.md, settings.json, .mcp.json, AGENTS.md — are
meant to give the agent context and tools. Users sometimes paste secrets
there because it's convenient ("here's my API key, use it when calling X").
Those files then get committed, shared, or synced — and the secret leaks.

Also detects invisible unicode characters (steganography) in config files,
using LLM Guard's approach (unicode categories Cf, Cc, Co via stdlib
unicodedata). This is how attackers hide instructions that LLMs will
execute but humans can't see.

Detection:
  Grep the contents of agent config files for known secret patterns AND
  scan for invisible unicode characters:
    - Anthropic keys (sk-ant-...)
    - OpenAI keys (sk-...)
    - GitHub PATs (ghp_, gho_, github_pat_)
    - AWS access keys (AKIA...)
    - Google API keys (AIza...)
    - Slack tokens (xoxb-, xoxp-)
    - Private key blocks
    - Generic high-entropy strings in obvious contexts
    - Invisible unicode (Cf, Cc, Co categories)

References:
  - ASAMM AI-05 (Value Constraint Mapping)
  - ASAMM AI-04 (Agent self-modification surfaces)
  - SecOps audit F-2
  - LLM Guard InvisibleText scanner (MIT)
  - OWASP AST04 (Insecure Metadata)
"""
from __future__ import annotations

import re
import unicodedata
from pathlib import Path
from typing import Iterable, List, Optional, Tuple

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# High-confidence secret patterns. These have distinctive prefixes/shapes.
SECRET_PATTERNS = [
    ("Anthropic API key",      re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{32,}")),
    ("OpenAI API key",         re.compile(r"\bsk-(?:proj-)?[a-zA-Z0-9]{32,}")),
    ("GitHub personal token",  re.compile(r"\b(?:ghp|gho|ghs|ghu|github_pat)_[a-zA-Z0-9_]{20,}")),
    ("AWS access key",         re.compile(r"\bAKIA[0-9A-Z]{16}")),
    ("AWS secret key",         re.compile(r"aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?", re.IGNORECASE)),
    ("Google API key",         re.compile(r"\bAIza[0-9A-Za-z_-]{35}")),
    ("Slack bot token",        re.compile(r"\bxox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{20,}")),
    ("Stripe secret key",      re.compile(r"\bsk_live_[0-9a-zA-Z]{24,}")),
    ("OpenRouter key",         re.compile(r"\bsk-or-(?:v\d+-)?[a-f0-9]{40,}")),
    ("HuggingFace token",      re.compile(r"\bhf_[a-zA-Z]{30,}")),
    ("Private key block",      re.compile(r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----")),
    ("JWT token",              re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
]

# Context patterns — lines like `api_key = "..."`, `token: "..."` that might
# contain secrets even if the secret doesn't match a known prefix. Lower
# confidence than pattern-matched, but still worth flagging.
CONTEXT_PATTERN = re.compile(
    r"""(?ix)                                    # case-insensitive, verbose
    (?:^|\s)                                     # line start or whitespace
    (api[_-]?key|secret|token|password|passwd|pwd|credential)
    \s*[:=]\s*                                   # assignment
    ['"]?                                        # optional quote
    ([A-Za-z0-9+/=_-]{20,})                      # high-entropy value
    ['"]?
    """,
)

# Files to scan. Relative to agent_home.
CONFIG_FILES = [
    "CLAUDE.md",
    "AGENTS.md",
    "settings.json",
    "settings.local.json",
    "mcp.json",
    ".mcp.json",
    "config.toml",
    "config.json",
]


def _scan_text(text: str, path: Path) -> List[Tuple[str, str, int, str]]:
    """Scan text for secrets. Returns (kind, matched_snippet, line_no, line_preview)."""
    hits: List[Tuple[str, str, int, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        # High-confidence pattern matches
        for kind, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                # Truncate the actual secret to first 8 chars + ... for evidence
                matched = m.group(0)
                redacted = matched[:8] + "..." if len(matched) > 12 else "<redacted>"
                preview = line.strip()[:150].replace(matched, redacted)
                hits.append((kind, redacted, line_no, preview))

        # Context-based matches (lower confidence)
        for cm in CONTEXT_PATTERN.finditer(line):
            value = cm.group(2)
            # Only flag if the value looks high-entropy (not obviously a placeholder)
            if _looks_like_secret(value):
                # Skip if already caught by high-confidence patterns above
                if any(value in h[1] or h[1] in value for h in hits if h[2] == line_no):
                    continue
                redacted = value[:4] + "..." if len(value) > 8 else "<redacted>"
                preview = line.strip()[:150].replace(value, redacted)
                hits.append((
                    f"{cm.group(1).lower()}-style assignment (low confidence)",
                    redacted,
                    line_no,
                    preview,
                ))
    return hits


def _looks_like_secret(value: str) -> bool:
    """Heuristic: is this a plausible secret vs a placeholder?"""
    if len(value) < 20:
        return False
    # Common placeholder patterns
    lower = value.lower()
    placeholders = [
        "your_", "example", "placeholder", "replace", "xxx", "yyy",
        "your-", "insert-", "fake", "test_key", "dummy",
    ]
    if any(p in lower for p in placeholders):
        return False
    # Must have some complexity
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return has_letter and has_digit


class SecretsInAgentConfig(Rule):
    id = "AI-05.secrets-in-agent-config"
    title = "Secrets embedded in agent configuration files"
    severity = Severity.HIGH
    references = [
        "ASAMM AI-05 (Value constraint mapping)",
        "SecOps audit F-2",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        # Scan both the agent_home directory and parent (project-level configs)
        roots = [agent_home]
        parent = agent_home.parent
        if parent != agent_home and parent.exists():
            roots.append(parent)

        seen_keys: set = set()
        for root in roots:
            for filename in CONFIG_FILES:
                path = root / filename
                if not path.exists() or not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                hits = _scan_text(text, path)
                for kind, redacted, line_no, preview in hits:
                    key = (str(path), line_no, kind)
                    if key in seen_keys:
                        continue
                    seen_keys.add(key)

                    # Private keys and cloud provider keys are critical
                    sev = self.severity
                    if "Private key" in kind or "AWS" in kind:
                        sev = Severity.CRITICAL
                    elif "low confidence" in kind:
                        sev = Severity.MEDIUM

                    yield Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=sev,
                        confidence=Confidence.HIGH if "low confidence" not in kind else Confidence.MEDIUM,
                        summary=(
                            f"Found what appears to be {kind} in {path.name} "
                            f"(line {line_no}). Agent config files are read by the "
                            f"agent on every session and may be committed, shared, "
                            f"or synced — secrets there leak easily."
                        ),
                        evidence=[
                            Evidence(
                                description=f"{path.name}:{line_no}",
                                source=path,
                                snippet=f"matched `{redacted}` in: {preview}",
                            ),
                        ],
                        remediation=(
                            "Move secrets to a .env file (add to .gitignore) and "
                            "reference them via environment variables in the agent "
                            "config. For MCP servers use `${ENV_VAR}` interpolation. "
                            "For secrets already committed to git, rewrite history "
                            "or rotate the credentials."
                        ),
                        references=self.references,
                    )


register_config_rule(SecretsInAgentConfig())


# =============================================================================
# AI-05.invisible-unicode — steganography in agent config files
# =============================================================================


# Characters we expect to see normally — not all Cf/Cc are malicious
_ACCEPTABLE_CONTROLS = {
    "\t", "\n", "\r", "\x0b", "\x0c",
}


def _scan_invisible_unicode(text: str) -> List[Tuple[int, int, str, str]]:
    """Find invisible / formatting / control characters in text.

    Returns list of (line_no, col, char_info, line_preview).

    Uses LLM Guard's approach: unicode categories Cf (Format), Cc (Control),
    Co (Private Use). We skip common whitespace (tab, newline, CR, VT, FF).
    """
    hits: List[Tuple[int, int, str, str]] = []
    for line_no, line in enumerate(text.splitlines(), 1):
        for col, ch in enumerate(line):
            if ch in _ACCEPTABLE_CONTROLS:
                continue
            cat = unicodedata.category(ch)
            if cat in ("Cf", "Cc", "Co"):
                codepoint = ord(ch)
                char_info = f"U+{codepoint:04X} ({cat}, name: {unicodedata.name(ch, '<no name>')})"
                # Line preview with char visualised
                visible = line.replace(ch, f"⟨U+{codepoint:04X}⟩")
                hits.append((line_no, col, char_info, visible[:150]))
    return hits


class InvisibleUnicodeInAgentConfig(Rule):
    """Detect hidden / zero-width / format characters in agent config files.

    Attackers embed invisible unicode in CLAUDE.md / AGENTS.md / tool
    descriptions so that LLMs see instructions humans can't. Examples:
      - zero-width joiner (\\u200d) used as instruction separator
      - bidi override (\\u202e) to reverse text visually
      - private use area (\\uE000-\\uF8FF) for custom encodings.

    Based on LLM Guard's InvisibleText scanner (MIT License, protectai/llm-guard).
    """

    id = "AI-05.invisible-unicode"
    title = "Invisible / steganographic unicode in agent config"
    severity = Severity.HIGH
    references = [
        "LLM Guard InvisibleText scanner (MIT) — protectai/llm-guard",
        "AGT MCP Security Scanner invisible unicode detection (MIT)",
        "OWASP AST04 (Insecure Metadata)",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        roots = [agent_home]
        parent = agent_home.parent
        if parent != agent_home and parent.exists():
            roots.append(parent)

        seen: set = set()
        for root in roots:
            for filename in CONFIG_FILES:
                path = root / filename
                if not path.exists() or not path.is_file():
                    continue
                try:
                    text = path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                hits = _scan_invisible_unicode(text)
                if not hits:
                    continue

                # Aggregate by char type so we don't emit 50 findings for
                # one file that's been "peppered" with zero-widths.
                by_char: dict = {}
                for line_no, col, info, preview in hits:
                    codepoint = info.split()[0]  # "U+200B"
                    by_char.setdefault(codepoint, []).append(
                        (line_no, col, info, preview)
                    )

                for codepoint, instances in by_char.items():
                    key = (str(path), codepoint)
                    if key in seen:
                        continue
                    seen.add(key)

                    first = instances[0]
                    n = len(instances)
                    line_no, col, info, preview = first

                    yield Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        confidence=Confidence.HIGH,
                        summary=(
                            f"Found {n} occurrence(s) of {info} in {path.name}. "
                            f"Invisible unicode in agent config files is a known "
                            f"technique for hiding instructions from users while "
                            f"LLMs still parse them. This may be intentional "
                            f"attack, unintentional copy-paste artifact, or "
                            f"typography (e.g. non-breaking space)."
                        ),
                        evidence=[
                            Evidence(
                                description=f"{path.name}:{line_no} col {col}",
                                source=path,
                                snippet=preview,
                            ),
                        ],
                        remediation=(
                            f"Inspect the file in a hex editor or with "
                            f"`python -c \"import sys; [print(hex(ord(c)), c) for c in open('{path.name}').read()]\"`. "
                            f"If the characters are not intentional (non-breaking space, RTL text), "
                            f"strip them — consider running content through a "
                            f"unicode normaliser before committing."
                        ),
                        references=self.references,
                    )


register_config_rule(InvisibleUnicodeInAgentConfig())
