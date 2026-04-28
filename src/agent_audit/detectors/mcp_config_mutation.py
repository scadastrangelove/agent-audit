"""AI-04.mcp-config-mutation — agent wrote to an MCP configuration file.

Motivated by OX Security's "Mother of All AI Supply Chains" research
(April 15, 2026) and CVE-2026-30615 (Windsurf). The canonical exploit:

  1. Attacker website serves different content to agent's internal fetches
  2. Agent receives injected instructions asking to edit mcp.json
  3. Agent proposes edit, user approves without seeing full diff
  4. New STDIO MCP entry executes immediately — RCE on victim's machine

The class of failure is distinct from generic persistence (AI-04):
  - AI-04.persistence-write: .bashrc, cron, systemd — affects shell sessions
  - AI-04.mcp-config-mutation: mcp.json — affects the AGENT ITSELF. The
    next invocation of the agent (or this same session in some tools)
    will execute any command the attacker put into the MCP entry.

Severity: CRITICAL regardless of content. An agent mutating its own
capability graph deserves review even if the change looks innocent.
LLM verifier can still downgrade legitimate cases (user explicitly
asked to add an MCP server).

References:
  - OX Security (Apr 15, 2026): "Mother of All AI Supply Chains"
    https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-technical-deep-dive/
  - CVE-2026-30615 (Windsurf prompt-injection → mcp.json → RCE)
  - LangFlow GHSA (915 public instances exposed via unauthed STDIO MCP)
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


# Paths that configure MCP servers or agent rules. Writing to any of
# these changes what the agent can execute next time.
#
# v0.7.4: narrowed after real-data feedback. Previously we flagged any
# CLAUDE.md / MEMORY.md / AGENTS.md write, but:
#   - Project-local CLAUDE.md is a LEGITIMATE project artifact (and
#     commonly edited by the agent per user request).
#   - ~/.claude/projects/<proj>/memory/MEMORY.md is Claude Code's
#     INTERNAL scratch memory — the agent is supposed to write there.
# The exploitable paths are:
#   - mcp.json / .mcp.json in ANY location (these directly register
#     STDIO commands that execute on next agent startup)
#   - .claude/settings.json (permission config)
#   - .cursorrules (silent rules override)
#   - claude_desktop_config.json / Windsurf/Cursor mcp.json
#   - agent instruction files such as CLAUDE.md / AGENTS.md / GEMINI.md
#     (including relative writes in the current repo)
_MCP_CONFIG_PATHS = re.compile(
    r"""
    (?:
        # MCP registration files — always dangerous to mutate
        (?:^|/)\.?mcp\.json\b                             # mcp.json, .mcp.json at any depth
      | claude_desktop_config\.json\b                    # Claude Desktop MCP config
      | \.cursor/mcp\.json\b
      | \.windsurf/mcp\.json\b | windsurf/mcp\.json\b
      | \.amazonq/mcp\.json\b | \.aws/amazonq/mcp\.json\b

        # Permission / rules config — silent policy change
      | \.claude/settings\.json\b                         # Claude Code settings
      | \.cursorrules\b                                   # Cursor rules (no gate)
      | \.codex/config\.toml\b                            # Codex approval config

        # Agent instruction files — local or global. Relative writes matter
        # too: changing ./CLAUDE.md alters the current repo's instruction
        # surface for future agent runs.
      | (?:^|/)(?:CLAUDE|AGENTS?|GEMINI)\.md$
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# STDIO config indicators inside the written content — elevate to
# CRITICAL when we can see these being added.
_STDIO_INDICATORS = re.compile(
    r"""
    (?:
        "command"\s*:\s*"[^"]+"               # JSON: "command": "..."
      | "transport"\s*:\s*"stdio"
      | "stdioServerParameters"
      | StdioServerParameters\s*\(
        # Dangerous command values frequently seen in exploit payloads
      | "command"\s*:\s*"(?:sh|bash|zsh|python|node|npx|curl|wget)"
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _is_write_tool(event: Event) -> Optional[str]:
    """Return target path if this is a write/edit event, else None."""
    if event.type != EventType.TOOL_USE:
        return None
    tool = (event.tool_name or "").lower()
    if tool not in ("write", "edit", "create_file", "str_replace", "str_replace_editor"):
        return None
    for key in ("file_path", "path", "filename"):
        v = (event.tool_input or {}).get(key)
        if isinstance(v, str):
            return v
    return None


def _bash_writes_mcp_config(event: Event) -> Optional[str]:
    """Return matched path if a Bash command writes to an MCP config."""
    if event.type != EventType.TOOL_USE:
        return None
    if (event.tool_name or "").lower() not in ("bash", "shell") and getattr(event, "canonical_tool", None) != "Bash":
        return None
    cmd = ""
    for k in ("command", "cmd", "script"):
        v = (event.tool_input or {}).get(k)
        if isinstance(v, str):
            cmd = v
            break
    if not cmd:
        return None

    # Patterns that write to files: echo >, tee, sed -i, heredoc
    # Look for `>` or `>>` near an MCP path, or sed -i on that path.
    # Paths can have .json/.md/.toml extension OR be known names without
    # extension (.cursorrules, CLAUDE.md, etc.) — we fall through to
    # _MCP_CONFIG_PATHS check anyway so regex above is mostly a fast filter.
    write_indicators = re.search(
        r"""
        (?:
            (?:>>?\s*|tee\s+(?:-a\s+)?)(?P<path1>[^\s|&;<]+)
          | sed\s+-i[^|&;<]*?(?P<path2>[^\s|&;<]+\.(?:json|md|toml|cursorrules))
          | cat\s*>\s*(?P<path3>[^\s|&;<]+)
        )
        """,
        cmd,
        re.VERBOSE | re.IGNORECASE,
    )
    if not write_indicators:
        return None
    target = (write_indicators.group("path1")
              or write_indicators.group("path2")
              or write_indicators.group("path3"))
    if target and _MCP_CONFIG_PATHS.search(target):
        return target
    return None


def _extract_write_content(event: Event) -> str:
    """Pull the content being written (for STDIO indicator check)."""
    if event.type != EventType.TOOL_USE:
        return ""
    # Write tool typically has "content" or "file_text"
    for key in ("content", "file_text", "text", "new_str"):
        v = (event.tool_input or {}).get(key)
        if isinstance(v, str):
            return v
    # Bash: peek at command body
    for key in ("command", "cmd", "script"):
        v = (event.tool_input or {}).get(key)
        if isinstance(v, str):
            return v
    return ""


class MCPConfigMutation(Rule):
    """Agent wrote to an MCP configuration or instruction file.

    Covers the OX Security / CVE-2026-30615 class: if prompt injection
    gets the agent to add a new STDIO MCP server entry, the next
    invocation executes arbitrary attacker-controlled commands.
    """

    id = "AI-04.mcp-config-mutation"
    title = "Agent mutated an MCP/agent configuration file"
    severity = Severity.CRITICAL
    references = [
        "OX Security (Apr 2026) — Mother of All AI Supply Chains technical deep dive",
        "CVE-2026-30615 — Windsurf prompt-injection to local RCE via mcp.json",
        "LangFlow GHSA — unauthenticated STDIO MCP config execution",
        "ASAMM AG-02 (MCP governance) + AI-04 (persistence)",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        for event in session.events:
            # Case A: direct write tool (Write/Edit/str_replace) to MCP path
            target = _is_write_tool(event)
            if target and _MCP_CONFIG_PATHS.search(target):
                yield from self._emit(session, event, target, via="direct_write")
                continue

            # Case B: bash command writing to MCP path
            bash_target = _bash_writes_mcp_config(event)
            if bash_target:
                yield from self._emit(session, event, bash_target, via="bash_redirect")
                continue

    def _emit(self, session: Session, event: Event, target: str, via: str):
        content = _extract_write_content(event)
        has_stdio = bool(_STDIO_INDICATORS.search(content))

        # Severity: CRITICAL if STDIO indicators present (active RCE vector).
        # Still HIGH even without — any mutation of agent's capability graph
        # needs review. LLM verifier downgrades legitimate cases.
        sev = Severity.CRITICAL if has_stdio else Severity.HIGH
        if session.is_subagent:
            if sev == Severity.CRITICAL:
                sev = Severity.HIGH
            elif sev == Severity.HIGH:
                sev = Severity.MEDIUM

        stdio_note = (
            " Content contains STDIO server indicators (command+transport) — "
            "next agent invocation may execute the embedded command."
            if has_stdio else
            " Content does not show obvious STDIO server indicators, but "
            "any mutation of an MCP config or agent-instruction file can "
            "change capability scope and warrants review."
        )

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=sev,
            confidence=Confidence.HIGH,
            summary=(
                f"Agent wrote to `{target}` (via {via}). This file is part "
                f"of the agent's configuration or instruction surface — "
                f"mutating it changes what the agent can execute or is "
                f"told to do.{stdio_note} This is the structural signature "
                f"of the OX Security MCP supply-chain class of attacks "
                f"(CVE-2026-30615 and related)."
            ),
            evidence=[
                Evidence(
                    description=f"Write to MCP/agent-config path",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(event.turn_index, event.turn_index),
                    snippet=f"target={target} via={via}",
                ),
                Evidence(
                    description="Written content (first 400 chars)",
                    source=session.source_file,
                    session_id=session.session_id,
                    turn_range=(event.turn_index, event.turn_index),
                    snippet=content[:400] if content else "(no content captured)",
                ),
            ],
            remediation=(
                "Review the written content against the user's request. "
                "If the user did not explicitly ask to add/modify an MCP "
                "server or agent instruction, treat this as prompt-injection "
                "outcome: revert the file, inspect any external content "
                "fetched earlier in the session for injected instructions. "
                "Longer-term: make MCP config files read-only to the agent "
                "(chmod 400 or add to the agent's deny-write list), or "
                "require human approval for any mutation to paths matching "
                "mcp.json/CLAUDE.md/AGENTS.md/.cursorrules."
            ),
            references=self.references,
            needs_llm_verification=True,
        )


register_session_rule(MCPConfigMutation())
