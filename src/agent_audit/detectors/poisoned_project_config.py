"""AI-05.poisoned-project-config — project-local agent config contains
malicious instructions.

Motivated by Check Point Research (Feb 2026) CVE-2025-59536 + CVE-2026-21852:
a malicious `.claude/project.json`, `.claude/hooks/`, or `.claude/mcp.json`
committed to a repository would be READ and EXECUTED by Claude Code
BEFORE the trust prompt appeared — enabling RCE and API key
exfiltration on any developer who opened the repo.

This is an INVERTED model of AI-04.mcp-config-mutation. That rule
catches the agent WRITING to mcp.json (outbound risk). This one catches
the agent READING project-local configs that ATTACKER wrote
(inbound risk).

Detection: for each unique cwd seen in session logs, walk the project
directory looking for `.claude/`, `.cursor/`, `.windsurf/`, `.vscode/`
agent-config folders. Inspect each file for suspicious content:
  - Shell commands in hooks (any hooks/* file content)
  - STDIO MCP server configs (writable-by-agent RCE vector)
  - Invisible unicode in instruction files (prompt injection)
  - References to sensitive paths outside cwd (~/.ssh, ~/.aws, ~/Downloads)
  - Exfil URLs (curl/wget to external hosts in instructions)

Severity: CRITICAL for shell-in-hooks or STDIO+external-host; HIGH for
invisible unicode or sensitive-path references; MEDIUM for soft
signals (overly broad permissions).

Scope: READ-ONLY inspection of files that already exist on disk. We
do NOT execute anything. Paths are checked for existence only if they
fall within the session's declared cwd (prevents path traversal via
malicious cwd).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

from ..events import Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


# Folders within a project that agents read config from.
_PROJECT_CONFIG_FOLDERS = (
    ".claude",
    ".cursor",
    ".windsurf",
    ".vscode",  # sometimes contains agent-related settings
    ".codex",
    ".amazonq",
    ".continue",
)


# Top-level files in a project that act as agent instructions.
_PROJECT_INSTRUCTION_FILES = (
    "CLAUDE.md",
    "AGENTS.md",
    "AGENT.md",
    "GEMINI.md",
    ".cursorrules",
    ".continuerules",
)


# File extensions we'll inspect. Others are skipped.
_INSPECTABLE_EXT = {".json", ".toml", ".md", ".txt", ".yaml", ".yml", ".sh", ".bash"}


# Suspicious content patterns inside config/instruction files.
_SHELL_IN_HOOK = re.compile(
    r"""
    (?:
        (?:^|[\s'"])(?:curl|wget)\s+[^|&;<>\s]+
      | (?:^|[\s'"])rm\s+-[a-zA-Z]*r
      | \b(?:bash|sh|zsh|python|node)\s+-c\s+['"]
      | chmod\s+\+x
      | /bin/(?:sh|bash)
      | system\s*\(\s*['"]
      | exec\s*\(\s*['"]
      | subprocess\.
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


_STDIO_MCP_INDICATOR = re.compile(
    r"""
    (?:
        "transport"\s*:\s*"stdio"
      | "command"\s*:\s*"(?:sh|bash|zsh|python|node|npx|curl|wget|eval)"
      | StdioServerParameters
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


_SENSITIVE_PATH_REF = re.compile(
    r"""
    (?:
        ~/\.ssh\b
      | ~/\.aws\b
      | ~/\.gcp\b
      | ~/\.gcloud\b
      | ~/\.kube\b
      | ~/Downloads\b
      | ~/Desktop\b
      | /etc/shadow\b
      | /etc/passwd\b
      | \.ssh/id_[rd]sa
      | \.aws/credentials
      | GOOGLE_APPLICATION_CREDENTIALS
      | AWS_SESSION_TOKEN
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


_EXFIL_URL = re.compile(
    r"""
    https?://
    (?!
        (?:
            localhost | 127\. | 0\.0\.0\.0
          | (?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.
          | api\.anthropic\.com | api\.openai\.com | api\.github\.com
          | raw\.githubusercontent\.com | githubusercontent\.com
          | registry\.npmjs\.org | pypi\.org
          | docs\.anthropic\.com
          # v0.8.0: IANA-reserved docs TLDs — explicitly NOT exfil,
          # always documentation placeholders.
          | example\.com | example\.org | example\.net
          | (?:[\w-]+\.)?example\.(?:com|org|net)
          | test\.invalid | localhost\.localdomain
        )
    )
    [\w.-]+
    """,
    re.VERBOSE,
)


# Invisible unicode — prompt injection classic (U+200B-U+200F, U+2060-U+2064,
# U+FEFF byte-order mark, variation selectors, tag characters).
_INVISIBLE_UNICODE = re.compile(
    "["
    "\u200b\u200c\u200d\u200e\u200f"   # zero-width joiners
    "\u2060\u2061\u2062\u2063\u2064"   # word joiner, function application
    "\ufeff"                            # byte-order mark
    "]"
)


MAX_FILE_SIZE_BYTES = 256 * 1024       # Don't read huge files
MAX_FILES_PER_PROJECT = 30             # Bounded scan
MAX_PROJECTS_PER_SCAN = 50             # Stop after this many distinct cwds


def _safe_read(p: Path) -> Optional[str]:
    """Bounded, exception-swallowing read. Returns None if can't read."""
    try:
        if not p.is_file():
            return None
        size = p.stat().st_size
        if size > MAX_FILE_SIZE_BYTES:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError):
        return None


def _classify_file(path: Path, content: str) -> List[Tuple[str, str, Severity]]:
    """Return list of (category, evidence_snippet, severity) findings
    for a single file."""
    findings: List[Tuple[str, str, Severity]] = []

    is_hook = "hook" in str(path).lower()
    is_mcp = path.name in ("mcp.json", ".mcp.json") or "mcp" in path.name.lower()

    # Shell commands in hook files are the Check Point case — CRITICAL
    if is_hook:
        m = _SHELL_IN_HOOK.search(content)
        if m:
            findings.append((
                "shell_in_hook",
                f"Hook file contains shell invocation: {m.group(0)[:80]}",
                Severity.CRITICAL,
            ))

    # STDIO MCP in project-local config — RCE vector on checkout
    if is_mcp:
        m = _STDIO_MCP_INDICATOR.search(content)
        if m:
            findings.append((
                "stdio_mcp_in_project",
                f"Project-local MCP config contains STDIO indicator: "
                f"{m.group(0)[:80]}",
                Severity.CRITICAL,
            ))

    # Invisible unicode — prompt injection
    inv_chars = _INVISIBLE_UNICODE.findall(content)
    if inv_chars:
        findings.append((
            "invisible_unicode",
            f"File contains {len(inv_chars)} invisible unicode character(s) — "
            f"classic prompt-injection vector",
            Severity.HIGH,
        ))

    # References to sensitive paths outside cwd
    sensitive_matches = _SENSITIVE_PATH_REF.findall(content)
    if sensitive_matches:
        findings.append((
            "sensitive_path_ref",
            f"References to sensitive paths: "
            f"{', '.join(set(sensitive_matches[:5]))}",
            Severity.HIGH,
        ))

    # External exfil URLs (not trusted sources)
    # v0.8.0: for markdown-style files (CLAUDE.md, AGENTS.md, .md config),
    # strip content inside ```fenced code blocks``` and `inline` code
    # before URL matching. URLs inside documentation code samples are
    # not attack surface — they're illustrative command examples.
    is_markdown = path.suffix.lower() == ".md" or path.name.lower() in (
        "claude.md", "agents.md", "agent.md", "gemini.md",
    )
    url_source = content
    if is_markdown:
        # Strip fenced code blocks (```...```)
        url_source = re.sub(r"```[\s\S]*?```", "", url_source)
        # Strip inline code (`...`)
        url_source = re.sub(r"`[^`\n]*`", "", url_source)

    exfil = _EXFIL_URL.findall(url_source)
    if exfil:
        # Deduplicate and limit
        uniq = list(set(exfil))[:3]
        findings.append((
            "external_url",
            f"References external URL(s) — potential exfil or fetch target: "
            f"{', '.join(uniq)}",
            Severity.MEDIUM,
        ))

    return findings


def _scan_project(project_root: Path) -> List[Tuple[Path, str, str, Severity]]:
    """Walk project_root's agent-config folders + instruction files and
    classify their contents. Returns list of (path, category, evidence,
    severity)."""
    results: List[Tuple[Path, str, str, Severity]] = []
    file_count = 0

    # Top-level instruction files
    for fname in _PROJECT_INSTRUCTION_FILES:
        if file_count >= MAX_FILES_PER_PROJECT:
            break
        fpath = project_root / fname
        if fpath.suffix.lower() not in _INSPECTABLE_EXT and fname not in (".cursorrules", ".continuerules"):
            continue
        content = _safe_read(fpath)
        if content is None:
            continue
        file_count += 1
        for cat, snip, sev in _classify_file(fpath, content):
            results.append((fpath, cat, snip, sev))

    # Config folder traversal
    for folder_name in _PROJECT_CONFIG_FOLDERS:
        folder = project_root / folder_name
        if not folder.is_dir():
            continue
        for fpath in folder.rglob("*"):
            if file_count >= MAX_FILES_PER_PROJECT:
                break
            if not fpath.is_file():
                continue
            # Hooks have no extension often; inspect all files in hooks/*
            is_in_hooks = "hooks" in fpath.parts
            if not is_in_hooks and fpath.suffix.lower() not in _INSPECTABLE_EXT:
                continue
            content = _safe_read(fpath)
            if content is None:
                continue
            file_count += 1
            for cat, snip, sev in _classify_file(fpath, content):
                results.append((fpath, cat, snip, sev))

    return results


class PoisonedProjectConfig(Rule):
    """Project-local agent config file contains malicious instructions."""

    id = "AI-05.poisoned-project-config"
    title = "Project-local agent config contains dangerous content"
    severity = Severity.CRITICAL  # default — categorize per-file
    references = [
        "Check Point Research (Feb 2026) — CVE-2025-59536 / CVE-2026-21852",
        "ASAMM AI-05 (Supply Chain), AI-06 (Prompt Injection)",
    ]

    def __init__(self) -> None:
        # Dedupe across sessions — one project dir scanned once per run
        self._scanned_roots: Set[Path] = set()
        self._projects_scanned = 0

    def check_session(self, session: Session, mode=None) -> Iterable[Finding]:
        cwd_str = session.cwd
        if not cwd_str:
            return

        try:
            project_root = Path(cwd_str).resolve()
        except (OSError, RuntimeError):
            return

        if not project_root.is_dir():
            return

        if project_root in self._scanned_roots:
            return

        if self._projects_scanned >= MAX_PROJECTS_PER_SCAN:
            return

        self._scanned_roots.add(project_root)
        self._projects_scanned += 1

        results = _scan_project(project_root)

        for fpath, category, snippet, severity in results:
            # Sub-agent doesn't apply — this is a project-scope finding
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"Project-local agent config at `{fpath}` contains "
                    f"suspicious content ({category}). Files under "
                    f"`.claude/`, `.cursor/`, `.windsurf/` and top-level "
                    f"instruction files like `CLAUDE.md`, `AGENTS.md` are "
                    f"read by agents — often BEFORE the user's trust "
                    f"prompt. This is the exact attack surface exploited "
                    f"by CVE-2025-59536 / CVE-2026-21852 (Check Point, "
                    f"Feb 2026)."
                ),
                evidence=[
                    Evidence(
                        description=f"Finding: {category}",
                        source=fpath,
                        snippet=snippet[:300],
                    ),
                ],
                remediation=(
                    f"Review `{fpath.name}` carefully. If you didn't author "
                    f"this file, treat the repository as potentially "
                    f"malicious:\n"
                    f"  • Do NOT open the project in a pre-2.0.65 Claude "
                    f"Code or pre-2.0 Cursor (version-vulnerable).\n"
                    f"  • Remove or review `.claude/hooks/` contents.\n"
                    f"  • Remove any STDIO MCP entries in `.claude/mcp.json` "
                    f"not authored by you.\n"
                    f"  • Rotate any credentials the agent had access to "
                    f"since first opening the repo."
                ),
                references=self.references,
                needs_llm_verification=True,
            )


# Register as session rule (we need access to session.cwd)
register_session_rule(PoisonedProjectConfig())
