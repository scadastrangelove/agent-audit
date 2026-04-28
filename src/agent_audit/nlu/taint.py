"""Event classification for taint-flow analysis.

Classifies tool_use events into taint sources and sinks to enable
causality-aware findings. This is a **heuristic** model — we don't have
true dynamic taint propagation because we work on forensic logs, not
runtime telemetry. Instead we infer "likely caused by" from temporal
order within autonomy windows.

See EDR_BACKLOG.md for what proper taint propagation would require.

Sources: where potentially untrusted data enters the agent's action loop.
Sinks:   where consequential / risky actions happen.
Chains:  source(s) → sink within a window, no user turn in between.

Zero dependencies beyond stdlib and our existing knowledge modules.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from ..events import Event, EventType, Session
from ..knowledge import aegis, aegis_paths


# =============================================================================
# Vocabulary
# =============================================================================


class TaintSource(str, Enum):
    """Where potentially untrusted / interesting data enters the agent."""
    USER_PROMPT = "user_prompt"
    WEB_RETRIEVED = "web_retrieved"         # WebFetch, WebSearch
    TOOL_OUTPUT = "tool_output"              # generic tool_result content
    SECRET_READ = "secret_read"              # Read on sensitive path
    DOWNLOAD = "download"                    # curl/wget/scp pulling content
    EXTERNAL_MEMORY = "external_memory"      # Read on mutable instruction files


class TaintSink(str, Enum):
    """Risky actions the agent can take."""
    SHELL_EXEC = "shell_exec"                # Bash/shell (all)
    SENSITIVE_WRITE = "sensitive_write"      # Write/Edit on sensitive path
    PACKAGE_INSTALL = "package_install"      # pip/npm/apt install
    NETWORK_EGRESS = "network_egress"        # outbound curl/wget/scp
    REPO_PUSH = "repo_push"                  # git push
    PERSISTENCE = "persistence"              # write to boot/login/cron
    DESTRUCTIVE = "destructive"              # rm -rf, DROP TABLE, etc.


# Paths that represent external/mutable instructions — reading these is a
# distinct taint source because their content can be weaponized as prompt
# injection payload (see CS10 in Agents of Chaos).
_EXTERNAL_MEMORY_PATHS = re.compile(
    r"""
    (?:
        CLAUDE\.md | AGENTS?\.md | MEMORY\.md | SOUL\.md
      | CONSTITUTION\.md | BIBLE\.md | GEMINI\.md | \.cursorrules
      | spiral_log\.md
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# =============================================================================
# Bash command classifiers
# =============================================================================


_DOWNLOAD_CMD = re.compile(
    r"""
    \b(?:
        curl\s+[^|&;]*https?://           # curl http...
      | wget\s+[^|&;]*https?://
      | git\s+clone\s
      | scp\s+[\w.-]+@
      | rsync\s+[^|&;]*::
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_NETWORK_EGRESS_CMD = re.compile(
    r"""
    \b(?:
        curl\s+[^|&;]*(?:-T|--upload-file|--data-binary|-F\s|-d\s+@|-X\s+(?:POST|PUT))
      | wget\s+[^|&;]*--post-file
      | scp\s+[\w./-]+\s+[\w.-]+@
      | rsync\s+[^|&;]*\s+[\w.-]+:
      | aws\s+s3\s+(?:cp|sync|mv)\s+[^|&;]+\s+s3://
      | gcloud\s+storage\s+cp
      | cat\s+\S+\s*\|\s*(?:curl|nc|ssh)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_PACKAGE_INSTALL_CMD = re.compile(
    r"""
    \b(?:
        pip\s+install | pip3\s+install | pipx\s+install
      | npm\s+install | pnpm\s+install | yarn\s+(?:add|install)
      | cargo\s+install | go\s+install | go\s+get
      | brew\s+install | apt\s+install | apt-get\s+install
      | dnf\s+install | yum\s+install | pacman\s+-S
      | gem\s+install | composer\s+(?:require|install)
      | curl\s+[^|&;]+\|\s*(?:sh|bash)       # pipe-to-shell
      | wget\s+[^|&;]+\|\s*(?:sh|bash)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_REPO_PUSH_CMD = re.compile(
    r"""
    \bgit\s+push\b
    """,
    re.VERBOSE | re.IGNORECASE,
)

_DESTRUCTIVE_CMD = re.compile(
    r"""
    \b(?:
        rm\s+-[a-zA-Z]*r[a-zA-Z]*f
      | rm\s+.*\.(?:db|sqlite|rdb)
      | DROP\s+(?:TABLE|DATABASE|SCHEMA)
      | TRUNCATE\s+TABLE
      | drop_all\(
      | terraform\s+destroy
      | kubectl\s+delete\s+(?:namespace|pvc)
      | git\s+push\s+--force | git\s+push\s+-f
      | git\s+reset\s+--hard
      | git\s+clean\s+-[a-z]*f[a-z]*d
      | prisma\s+.*--accept-data-loss
      | alembic\s+downgrade\s+base
      | aws\s+(?:s3\s+rb\s+--force|rds\s+delete)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


# =============================================================================
# Destination classification for network
# =============================================================================


_LOCALHOST_RE = re.compile(
    r"""
    (?:^|[^\w.])
    (?:
        localhost
      | 127\.\d+\.\d+\.\d+
      | 0\.0\.0\.0
      | 10\.\d+\.\d+\.\d+
      | 192\.168\.\d+\.\d+
      | 172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+
      | ::1
      | \[::1\]
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _extract_url_host(cmd: str) -> Optional[str]:
    """Pull hostname from first URL in a bash command."""
    m = re.search(r"https?://([\w.-]+)", cmd)
    if m:
        return m.group(1).lower()
    # scp/ssh user@host:path
    m = re.search(r"[\w.-]+@([\w.-]+)[:\s]", cmd)
    if m:
        return m.group(1).lower()
    return None


def is_localhost(host_or_cmd: str) -> bool:
    """True if destination is localhost or private network."""
    return bool(_LOCALHOST_RE.search(host_or_cmd))


# Subdomains that host arbitrary user content — even under "known agent"
# parent domains, a fetch here is NOT trusted. `gist.github.com` serves
# user-created gists; `raw.githubusercontent.com` serves user-created files.
# These can be weaponized as prompt injection payloads.
_UNTRUSTED_CONTENT_SUBDOMAINS = re.compile(
    r"""
    ^(?:
        gist\.
      | raw\.
      | pastebin\.
      | codeberg\.
      | gitlab-raw\.
      | bitbucket-raw\.
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def classify_destination(host: str) -> str:
    """Classify a destination hostname: 'localhost' | 'known:<agent>' | 'user_content' | 'external'.

    'user_content' marks subdomains that serve arbitrary user-generated
    content (gist.github.com, raw.githubusercontent.com, etc.) — these
    sit under known-agent-vendor TLDs but should NOT be trusted as
    first-party content.
    """
    if is_localhost(host):
        return "localhost"
    if _UNTRUSTED_CONTENT_SUBDOMAINS.match(host):
        return "user_content"
    known = aegis.is_known_agent_domain(host)
    if known:
        return f"known:{known}"
    return "external"


# =============================================================================
# Event classification
# =============================================================================


@dataclass(frozen=True)
class EventClassification:
    """A single event can be source, sink, or both.

    E.g. WebFetch is a source (brings external content in). Bash(curl)
    can be both source (if it downloads) and sink (network egress).
    """
    sources: tuple = ()       # tuple of TaintSource
    sinks: tuple = ()         # tuple of TaintSink
    details: dict = field(default_factory=dict)   # e.g. path, host, cmd snippet


def _read_target(event: Event) -> Optional[str]:
    for key in ("file_path", "path", "filename", "file"):
        value = (event.tool_input or {}).get(key)
        if isinstance(value, str):
            return value
    return None


def _bash_cmd(event: Event) -> Optional[str]:
    for key in ("command", "cmd", "script"):
        value = (event.tool_input or {}).get(key)
        if isinstance(value, str):
            return value
    return None


def classify_event(event: Event) -> EventClassification:
    """Classify a tool_use event into taint sources and sinks.

    Returns empty classification for events that don't carry taint signal.
    """
    if event.type == EventType.USER_MESSAGE:
        return EventClassification(
            sources=(TaintSource.USER_PROMPT,),
            details={"text_len": len(event.text or "")},
        )
    if event.type == EventType.TOOL_RESULT:
        return EventClassification(
            sources=(TaintSource.TOOL_OUTPUT,),
            details={},
        )
    if event.type != EventType.TOOL_USE:
        return EventClassification()

    tool_name = (event.tool_name or "").lower()
    # v0.9.0: canonical_tool cross-agent layer. Codex's exec_command,
    # apply_patch, read_file, write_stdin now flow through same
    # classification branches as Claude's Bash/Edit/Read. Before v0.9.0
    # the taint engine was tool_name-centric and silently skipped all
    # Codex tool events — which left 10 rules (C2/C3/AI-04/AI-06/
    # AD-02/advice) Codex-blind despite v0.8.2 detector-level patches,
    # because those detectors feed off taint classification and got
    # empty EventClassification() for every Codex event.
    canonical = getattr(event, "canonical_tool", None)
    sources: List[TaintSource] = []
    sinks: List[TaintSink] = []
    details: dict = {"tool": event.tool_name}
    if canonical:
        details["canonical_tool"] = canonical

    is_read = tool_name in ("read", "view") or canonical == "Read"
    is_web = (tool_name in ("webfetch", "web_fetch", "websearch",
                            "web_search", "fetch")
              or canonical in ("WebFetch", "WebSearch"))
    is_write = (tool_name in ("write", "edit", "create_file",
                              "str_replace_editor", "str_replace",
                              "multiedit", "notebook_edit")
                or canonical in ("Write", "Edit", "Patch"))
    is_bash = tool_name in ("bash", "shell") or canonical == "Bash"

    # --- Read-style tools ---
    if is_read:
        target = _read_target(event)
        if target:
            details["target"] = target
            match = aegis_paths.classify_path(target)
            if match:
                sources.append(TaintSource.SECRET_READ)
                details["path_category"] = match.top_category
            if _EXTERNAL_MEMORY_PATHS.search(target):
                sources.append(TaintSource.EXTERNAL_MEMORY)

    # --- Web fetchers ---
    elif is_web:
        sources.append(TaintSource.WEB_RETRIEVED)
        url = (event.tool_input or {}).get("url") or (event.tool_input or {}).get("query", "")
        if isinstance(url, str):
            details["url"] = url
            host = _extract_url_host(url) or url
            details["destination"] = classify_destination(host)

    # --- Write-style tools ---
    elif is_write:
        target = _read_target(event)
        if target:
            details["target"] = target
            match = aegis_paths.classify_path(target)
            if match:
                sinks.append(TaintSink.SENSITIVE_WRITE)
                details["path_category"] = match.top_category
            # Persistence — reuse the paths persistence_write cares about
            if re.search(
                r"(\.bashrc|\.zshrc|\.profile|crontab|systemd|init\.d|/etc/|"
                r"launchd|LaunchAgents|LaunchDaemons|autostart|startup)",
                target, re.IGNORECASE,
            ):
                sinks.append(TaintSink.PERSISTENCE)

    # --- Bash/shell ---
    elif is_bash:
        cmd = _bash_cmd(event)
        if cmd:
            details["cmd"] = cmd[:200]
            # Always a shell exec sink
            sinks.append(TaintSink.SHELL_EXEC)

            # Downloads bring external content in (source)
            if _DOWNLOAD_CMD.search(cmd):
                sources.append(TaintSource.DOWNLOAD)
                host = _extract_url_host(cmd)
                if host:
                    details["src_host"] = host
                    details["src_destination"] = classify_destination(host)

            # Network egress sink
            if _NETWORK_EGRESS_CMD.search(cmd):
                sinks.append(TaintSink.NETWORK_EGRESS)
                host = _extract_url_host(cmd)
                if host:
                    details["egress_host"] = host
                    details["egress_destination"] = classify_destination(host)

            # Package install
            if _PACKAGE_INSTALL_CMD.search(cmd):
                sinks.append(TaintSink.PACKAGE_INSTALL)

            # Repo push
            if _REPO_PUSH_CMD.search(cmd):
                sinks.append(TaintSink.REPO_PUSH)

            # Destructive
            if _DESTRUCTIVE_CMD.search(cmd):
                sinks.append(TaintSink.DESTRUCTIVE)

            # `cat <sensitive_path>` = sensitive read via shell
            m = re.search(
                r"\b(?:cat|less|head|tail|more|bat)\s+[^|&;]*?(\S+\.(?:env|pem|key)|[~/]\.(?:ssh|aws|azure|gcloud)[^|\s&]*)",
                cmd, re.IGNORECASE,
            )
            if m:
                path = m.group(1)
                if aegis_paths.classify_path(path):
                    sources.append(TaintSource.SECRET_READ)
                    details["secret_path"] = path

    return EventClassification(
        sources=tuple(sources),
        sinks=tuple(sinks),
        details=details,
    )


# =============================================================================
# Heuristic causality chains
# =============================================================================


@dataclass
class TaintChain:
    """A causality-inferred chain: sources → sink within one autonomy window.

    'Heuristic' because we use temporal order as a proxy for causality —
    sources that appeared in the window before the sink are presumed
    relevant. This is not guaranteed, but it's the best we can do
    without dynamic taint propagation (see EDR_BACKLOG.md).
    """
    sources: tuple                         # tuple of (TaintSource, dict)
    sink: TaintSink
    sink_event: Event
    sink_details: dict = field(default_factory=dict)
    gap_turns: int = 0                     # turns between first source and sink
    has_user_turn_between: bool = False


def find_chains_in_window(window_events: List[Event]) -> List[TaintChain]:
    """For each sink in the window, walk backwards to gather sources.

    A "window" here is typically one autonomy span (between user messages).
    The window may include one leading user message (the one that started
    the autonomy span) — that's a normal boundary, not a user intervention
    mid-chain. True mid-chain user interventions (user talking while agent
    is acting) are what has_user_turn_between is meant to flag.
    """
    if not window_events:
        return []

    # Classify all events once
    classifications: List[Tuple[Event, EventClassification]] = [
        (e, classify_event(e)) for e in window_events
    ]

    # Identify the "leading user message" — the one that started this
    # autonomy span. If the first event is a user message, that's it.
    # Any later user message is a mid-chain intervention.
    leading_user_idx = -1
    if classifications and classifications[0][0].type == EventType.USER_MESSAGE:
        leading_user_idx = 0

    chains: List[TaintChain] = []

    # For each sink, walk backward collecting sources
    for i, (sink_ev, sink_cls) in enumerate(classifications):
        if not sink_cls.sinks:
            continue

        for sink_type in sink_cls.sinks:
            collected_sources: List[Tuple[TaintSource, dict]] = []
            user_between = False
            for j in range(i - 1, -1, -1):
                prior_ev, prior_cls = classifications[j]
                if prior_ev.type == EventType.USER_MESSAGE:
                    # Collect user prompt as a source
                    for s in prior_cls.sources:
                        collected_sources.append((s, prior_cls.details))
                    # Only flag as mid-chain intervention if this is NOT
                    # the leading user message
                    if j != leading_user_idx:
                        user_between = True
                    break
                for s in prior_cls.sources:
                    collected_sources.append((s, prior_cls.details))

            if not collected_sources:
                continue

            first_source_turn = window_events[max(0, i - len(collected_sources))].turn_index
            gap = sink_ev.turn_index - first_source_turn

            chains.append(TaintChain(
                sources=tuple(collected_sources),
                sink=sink_type,
                sink_event=sink_ev,
                sink_details=sink_cls.details,
                gap_turns=gap,
                has_user_turn_between=user_between,
            ))

    return chains


def score_chain(chain: TaintChain) -> float:
    """Risk score 0.0-1.0 for a taint chain.

    Higher = more suspicious. Caller uses this to prioritise findings
    for LLM verification.
    """
    score = 0.0
    source_types = {s for s, _ in chain.sources}

    # Sink-type base weights
    base = {
        TaintSink.DESTRUCTIVE: 0.5,
        TaintSink.PERSISTENCE: 0.5,
        TaintSink.NETWORK_EGRESS: 0.4,
        TaintSink.REPO_PUSH: 0.3,
        TaintSink.PACKAGE_INSTALL: 0.3,
        TaintSink.SENSITIVE_WRITE: 0.3,
        TaintSink.SHELL_EXEC: 0.1,
    }.get(chain.sink, 0.1)
    score += base

    # External sources amplify the sink
    if TaintSource.WEB_RETRIEVED in source_types:
        # Only if the fetch went to external/user_content destination
        for _, d in chain.sources:
            dest = d.get("destination", "")
            if dest in ("external", "user_content"):
                score += 0.25
                break
            elif dest.startswith("known:"):
                # Known agent first-party domain — less suspicious
                score += 0.05
                break
    if TaintSource.EXTERNAL_MEMORY in source_types:
        score += 0.2  # mutable instructions are strong injection vector
    if TaintSource.SECRET_READ in source_types:
        score += 0.2  # secrets + any sink is concerning
    if TaintSource.DOWNLOAD in source_types:
        for _, d in chain.sources:
            dest = d.get("src_destination", "")
            if dest in ("external", "user_content"):
                score += 0.15

    # User turn between = they approved the transition, less risky
    if chain.has_user_turn_between:
        score -= 0.2

    return max(0.0, min(1.0, score))


# =============================================================================
# Window summary (for CST)
# =============================================================================


def summarise_window(window_events: List[Event]) -> dict:
    """Produce a compact taint summary for a window.

    Used by cst.py to build the Compact Sandbox Trace.
    """
    chains = find_chains_in_window(window_events)

    # Per-category scores (suspicious_subgraph_score in CST)
    category_scores: Dict[str, float] = {
        "destructive": 0.0,
        "persistence": 0.0,
        "secret_access": 0.0,
        "egress": 0.0,
        "injection": 0.0,
    }
    for chain in chains:
        s = score_chain(chain)
        if chain.sink == TaintSink.DESTRUCTIVE:
            category_scores["destructive"] = max(category_scores["destructive"], s)
        if chain.sink == TaintSink.PERSISTENCE:
            category_scores["persistence"] = max(category_scores["persistence"], s)
        if chain.sink == TaintSink.NETWORK_EGRESS:
            category_scores["egress"] = max(category_scores["egress"], s)
        if any(src == TaintSource.SECRET_READ for src, _ in chain.sources):
            category_scores["secret_access"] = max(category_scores["secret_access"], s)
        if any(src == TaintSource.EXTERNAL_MEMORY or src == TaintSource.WEB_RETRIEVED
               for src, _ in chain.sources):
            category_scores["injection"] = max(category_scores["injection"], s)

    # Compact chain representation — top 5 by score
    chains_sorted = sorted(chains, key=score_chain, reverse=True)[:5]
    compact_chains = []
    for chain in chains_sorted:
        source_labels = []
        for src, d in chain.sources:
            label = src.value
            if d.get("destination"):
                label += f":{d['destination']}"
            elif d.get("path_category"):
                label += f":{d['path_category']}"
            source_labels.append(label)
        compact_chains.append({
            "sources": source_labels[:5],
            "sink": chain.sink.value,
            "sink_target": chain.sink_details.get("target") or
                           chain.sink_details.get("cmd", "")[:80] or
                           chain.sink_details.get("tool", ""),
            "gap_turns": chain.gap_turns,
            "user_turn_between": chain.has_user_turn_between,
            "score": round(score_chain(chain), 2),
        })

    return {
        "chains": compact_chains,
        "subgraph_scores": {k: round(v, 2) for k, v in category_scores.items()},
        "chain_count": len(chains),
    }
