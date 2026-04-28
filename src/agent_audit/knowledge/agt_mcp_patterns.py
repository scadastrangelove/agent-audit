"""MCP tool poisoning patterns — adapted from Microsoft AGT.

Source: github.com/microsoft/agent-governance-toolkit/packages/agent-os/src/
        agent_os/mcp_security.py (MIT License, Copyright (c) Microsoft Corporation).

AGT's MCP Security Scanner ships ~35 regex patterns across 8 categories used
to detect adversarial manipulation of MCP tool definitions. Attackers embed
hidden instructions in tool descriptions or schemas that are invisible to
users but executed by LLMs.

We import the patterns verbatim (same string content) and apply them in
a different execution context — forensic scanning of MCP configs on disk
— instead of AGT's pre-execution policy gate.

Categories imported:
  - invisible_unicode (5 patterns): zero-width spaces, bidi overrides, BOM,
    soft hyphens, word joiners
  - hidden_comments (3): HTML <!--...-->, markdown [//]:#(), [comment]:<>()
  - hidden_instructions (8): "ignore previous", "override", "instead of",
    "actually do", "system:", "assistant:", "do not follow", "disregard"
  - encoded_payloads (2): long base64 blobs, hex \\xNN sequences
  - exfiltration (8): curl, wget, fetch(, http://, send email, send to,
    post to, "include the contents of"
  - privilege_escalation (6): sudo, admin access, root access, elevate
    privilege, exec(, eval(
  - role_override (6): "you are", "your task is", "respond with",
    "always return", "you must", "your role is"
  - excessive_whitespace (1): \\n{5,}.+

Plus:
  - suspicious_decoded_keywords: check decoded base64 for keywords that
    suggest the encoded content is an instruction rather than data
  - suspicious_schema_fields: required field names that indicate the tool
    accepts arbitrary code or callback URLs
"""
from __future__ import annotations

import re
from typing import List, Pattern, Tuple


# =============================================================================
# Pattern sets — verbatim from AGT (strings identical; we compile them)
# =============================================================================

INVISIBLE_UNICODE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"[\u200b\u200c\u200d\ufeff]"),   # zero-width / BOM
    re.compile(r"[\u202a-\u202e]"),              # bidi embedding/override
    re.compile(r"[\u2066-\u2069]"),              # bidi isolates
    re.compile(r"[\u00ad]"),                     # soft hyphen
    re.compile(r"[\u2060\u180e]"),               # word joiner, MVS
]

HIDDEN_COMMENT_PATTERNS: List[Pattern[str]] = [
    re.compile(r"<!--.*?-->", re.DOTALL),
    re.compile(r"\[//\]:\s*#\s*\(.*?\)", re.DOTALL),
    re.compile(r"\[comment\]:\s*<>\s*\(.*?\)", re.DOTALL),
]

HIDDEN_INSTRUCTION_PATTERNS: List[Pattern[str]] = [
    re.compile(r"ignore\s+(all\s+)?previous", re.IGNORECASE),
    re.compile(r"override\s+(the\s+)?(previous|above|original)", re.IGNORECASE),
    re.compile(r"instead\s+of\s+(the\s+)?(above|previous|described)", re.IGNORECASE),
    re.compile(r"actually\s+do", re.IGNORECASE),
    re.compile(r"\bsystem\s*:", re.IGNORECASE),
    re.compile(r"\bassistant\s*:", re.IGNORECASE),
    re.compile(r"do\s+not\s+follow", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?(above|prior|previous)", re.IGNORECASE),
]

ENCODED_PAYLOAD_PATTERNS: List[Pattern[str]] = [
    re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),     # long base64
    re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}"),    # hex escape sequences
]

EXFILTRATION_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bcurl\b", re.IGNORECASE),
    re.compile(r"\bwget\b", re.IGNORECASE),
    re.compile(r"\bfetch\s*\(", re.IGNORECASE),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\bsend\s+email\b", re.IGNORECASE),
    re.compile(r"\bsend\s+to\b", re.IGNORECASE),
    re.compile(r"\bpost\s+to\b", re.IGNORECASE),
    re.compile(r"include\s+the\s+contents?\s+of\b", re.IGNORECASE),
]

PRIVILEGE_ESCALATION_PATTERNS: List[Pattern[str]] = [
    re.compile(r"\bsudo\b", re.IGNORECASE),
    re.compile(r"\badmin\s+access\b", re.IGNORECASE),
    re.compile(r"\broot\s+access\b", re.IGNORECASE),
    re.compile(r"\belevate\s+privile", re.IGNORECASE),
    re.compile(r"\bexec\s*\(", re.IGNORECASE),
    re.compile(r"\beval\s*\(", re.IGNORECASE),
]

ROLE_OVERRIDE_PATTERNS: List[Pattern[str]] = [
    re.compile(r"you\s+are\b", re.IGNORECASE),
    re.compile(r"your\s+task\s+is\b", re.IGNORECASE),
    re.compile(r"respond\s+with\b", re.IGNORECASE),
    re.compile(r"always\s+return\b", re.IGNORECASE),
    re.compile(r"you\s+must\b", re.IGNORECASE),
    re.compile(r"your\s+role\s+is\b", re.IGNORECASE),
]

EXCESSIVE_WHITESPACE_PATTERN: Pattern[str] = re.compile(r"\n{5,}.+", re.DOTALL)

SUSPICIOUS_DECODED_KEYWORDS: List[str] = [
    "ignore", "override", "system", "password", "secret", "admin",
    "root", "exec", "eval", "import os", "send", "curl", "fetch",
]

SUSPICIOUS_SCHEMA_FIELDS: List[str] = [
    "system_prompt", "instructions", "override", "command", "exec",
    "eval", "callback_url", "webhook", "target_url",
]


# =============================================================================
# Analysis helpers
# =============================================================================

def scan_description(text: str) -> List[Tuple[str, str, str]]:
    """Scan an MCP tool description for poisoning patterns.

    Returns list of (category, severity, match_preview) tuples.
    """
    findings: List[Tuple[str, str, str]] = []

    for p in INVISIBLE_UNICODE_PATTERNS:
        m = p.search(text)
        if m:
            findings.append((
                "invisible_unicode", "critical",
                f"char U+{ord(m.group()[0]):04X}",
            ))
            break  # one per category is enough

    for p in HIDDEN_COMMENT_PATTERNS:
        m = p.search(text)
        if m:
            findings.append((
                "hidden_comment", "critical",
                m.group()[:80],
            ))
            break

    for p in HIDDEN_INSTRUCTION_PATTERNS:
        m = p.search(text)
        if m:
            findings.append((
                "hidden_instruction", "critical",
                f"pattern: {p.pattern}",
            ))
            break

    if EXCESSIVE_WHITESPACE_PATTERN.search(text):
        findings.append((
            "excessive_whitespace", "medium",
            "instructions hidden after 5+ blank lines",
        ))

    for p in ENCODED_PAYLOAD_PATTERNS:
        m = p.search(text)
        if m:
            findings.append((
                "encoded_payload", "high",
                f"matched pattern: {p.pattern[:40]}",
            ))
            break

    for p in ROLE_OVERRIDE_PATTERNS:
        if p.search(text):
            findings.append((
                "role_override", "medium",
                f"pattern: {p.pattern}",
            ))
            break

    for p in EXFILTRATION_PATTERNS:
        if p.search(text):
            findings.append((
                "exfiltration_hint", "high",
                f"pattern: {p.pattern}",
            ))
            break

    for p in PRIVILEGE_ESCALATION_PATTERNS:
        if p.search(text):
            findings.append((
                "privilege_escalation_hint", "high",
                f"pattern: {p.pattern}",
            ))
            break

    return findings


def scan_schema_field_name(field_name: str) -> bool:
    """Check if a schema field name is suspicious (per AGT's list).

    Returns True if the field name matches any of AGT's suspicious names.
    """
    lower = field_name.lower()
    return any(sus in lower for sus in SUSPICIOUS_SCHEMA_FIELDS)
