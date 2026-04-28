"""Agent-task YAML surface adapter (D-9 from AST Precision Plan).

Recognises multi-agent framework task configs — YAML files that embed
system prompts and agent descriptions directly as YAML fields. These
configs ARE instruction surfaces for the framework's agents but don't
match the SKILL.md / AGENTS.md / MCP-manifest signatures our main
file classifier looks for.

Known frameworks following this shape (signature-detected, not hardcoded):
- OpenBMB/AgentVerse (`agentverse/tasks/**/*.yaml`) — `prompts` + `agents`
- AutoGen-style task configs
- CrewAI-style agent definitions

Detection signature (conservative, rejects non-agent YAMLs):
- YAML top-level has `agents` OR `prompts` (with non-empty values)
- AND one of: `agents` contains `prompt`/`role_description`/`system_message`
  sub-field, OR top-level has `task_description`/`environment`/`tools`

When a file matches, we extract prompt-like string fields and expose them
as concatenated "pseudo-markdown prose" that native detectors can run
on (capability lexicon, identity lexicon).

The adapter is conservative by design — a generic YAML with
`agents: [alice, bob]` (no prompts inside) doesn't match. We want zero
FP on unrelated YAML configs in node_modules/ or CI config dirs.
"""
from __future__ import annotations

from pathlib import Path
from typing import List, Optional

try:
    import yaml  # type: ignore
except ImportError:
    yaml = None


# Fields at the top level that strongly suggest an agent-task config.
# Any ONE of these being present alongside `agents` or `prompts` is enough.
_CONFIRMATION_FIELDS = {
    "task_description", "environment", "tools", "tool_config",
    "evaluation_dimensions", "max_rounds", "max_turns", "max_turn",
    "max_inner_turns", "max_loop_rounds", "max_criticizing_rounds",
    "cnt_agents", "cnt_critic_agents", "cnt_tool_agents",
}

# Fields inside `agents` (or individual agent dicts) that carry prompt-like text
_AGENT_PROMPT_FIELDS = {
    "prompt", "role_description", "system_message", "system_prompt",
    "description", "role", "backstory", "goal", "instructions",
}

# Fields at top level that themselves carry prompt content
_TOP_LEVEL_PROMPT_FIELDS = {
    "prompts", "prompt", "system_prompt", "system_message", "instructions",
}


def is_agent_task_config(path: Path, text: Optional[str] = None) -> bool:
    """Return True if the YAML file looks like an agent-task config.

    Quick signature check — does NOT fire on ordinary YAML (docker-compose,
    CI configs, package manifests).
    """
    if yaml is None:
        return False
    if path.suffix.lower() not in {".yaml", ".yml"}:
        return False
    try:
        content = text if text is not None else path.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return False
    # Fast reject: if content doesn't mention any of the signal words, skip
    lower = content.lower()
    if not ("agent" in lower or "prompt" in lower):
        return False
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return False
    if not isinstance(doc, dict):
        return False
    top_keys = set(doc.keys())

    # Must have `agents` OR one of the top-level prompt fields
    has_agents = "agents" in top_keys and doc.get("agents")
    has_prompts = any(
        f in top_keys and doc.get(f) for f in _TOP_LEVEL_PROMPT_FIELDS
    )
    if not (has_agents or has_prompts):
        return False

    # Require a confirming field OR agent-internal prompt field
    if top_keys & _CONFIRMATION_FIELDS:
        return True

    # Check inside `agents` for prompt-carrying subfields
    agents = doc.get("agents")
    if isinstance(agents, list):
        for a in agents:
            if isinstance(a, dict) and (set(a.keys()) & _AGENT_PROMPT_FIELDS):
                return True
    elif isinstance(agents, dict):
        if set(agents.keys()) & _AGENT_PROMPT_FIELDS:
            return True
        for v in agents.values():
            if isinstance(v, dict) and (set(v.keys()) & _AGENT_PROMPT_FIELDS):
                return True

    return False


def extract_instruction_text(path: Path, text: Optional[str] = None) -> str:
    """Pull all prompt-like string fields from an agent-task YAML,
    concatenated as pseudo-prose so native detectors can run on it.

    Returns empty string if parse fails or file doesn't match signature.
    Callers should check is_agent_task_config() first for performance,
    but this function is defensive and safe to call on anything.
    """
    if yaml is None:
        return ""
    try:
        content = text if text is not None else path.read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError:
        return ""
    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return ""
    if not isinstance(doc, dict):
        return ""

    parts: List[str] = []

    def _collect_strings(node, depth: int = 0, in_container: bool = False):
        """Collect prompt-like strings from YAML tree.

        `in_container=True` means we're already inside an `agents`/`tools`
        block — so ANY nested dict (e.g. a named agent like `researcher:`)
        should be recursed into regardless of key.
        """
        if depth > 6:
            return
        if isinstance(node, str):
            s = node.strip()
            if len(s) >= 40:  # skip short identifiers
                parts.append(s)
        elif isinstance(node, list):
            for item in node:
                _collect_strings(item, depth + 1, in_container=in_container)
        elif isinstance(node, dict):
            for k, v in node.items():
                # Always recurse into prompt-bearing fields
                if k in (_TOP_LEVEL_PROMPT_FIELDS | _AGENT_PROMPT_FIELDS):
                    _collect_strings(v, depth + 1, in_container=in_container)
                # Recurse into `agents` container — and mark children as in-container
                elif k == "agents":
                    _collect_strings(v, depth + 1, in_container=True)
                # Recurse into `tools` — tool descriptions matter
                elif k in {"tools", "tool_config"}:
                    _collect_strings(v, depth + 1, in_container=True)
                # Also recurse into task_description / environment
                elif k in {"task_description", "environment"}:
                    _collect_strings(v, depth + 1, in_container=in_container)
                # Inside agents/tools, recurse into every value regardless of key
                # (this catches `researcher: {...}` style dicts with agent names
                #  as keys)
                elif in_container:
                    _collect_strings(v, depth + 1, in_container=in_container)

    _collect_strings(doc)
    return "\n\n".join(parts)
