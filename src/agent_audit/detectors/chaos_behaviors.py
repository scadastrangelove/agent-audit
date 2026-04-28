"""Behavioral detectors from the Agents of Chaos paper.

Three detectors covering distinct failure modes observed in the paper:
  - resource.unbounded-loop (CS4, CS5) — repetitive tool calls without
    progress, resource exhaustion
  - behavior.cascading-destructive-chain (CS6) — multiple destructive
    actions with escalating severity in one autonomy window
  - AI-06.indirect-prompt-injection-vector (CS10) — external content
    fetch followed by unplanned destructive/sensitive action

References:
  - "Agents of Chaos" (arXiv:2602.20021, Feb 2026)
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from typing import Iterable, List, Optional, Tuple

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


# =============================================================================
# resource.unbounded-loop (CS4, CS5)
# =============================================================================


def _tool_signature(event: Event) -> str:
    """Hash-stable representation of (tool_name + input), for loop detection.

    Two tool calls with identical signature are strongly suspected of being
    a repeat — agents don't normally call the exact same tool with the exact
    same args unless they're stuck.
    """
    if event.type != EventType.TOOL_USE:
        return ""
    name = (event.tool_name or "").lower()
    # Canonicalise input dict — sort keys, stringify
    try:
        input_str = json.dumps(event.tool_input or {}, sort_keys=True, default=str)
    except (TypeError, ValueError):
        input_str = str(event.tool_input)
    h = hashlib.md5(f"{name}|{input_str}".encode("utf-8")).hexdigest()[:12]
    return h


class UnboundedLoop(Rule):
    """Repetitive tool calls without progress — CS4 / CS5 from Agents of Chaos.

    Signals we aggregate:
      1. Same tool+input signature appears N+ times in one autonomy window.
      2. Tool call count in a window exceeds a hard threshold (already
         covered by C3.autonomy-window-excess but we add a specific
         'stuck in loop' flavour with different remediation).

    Severity escalates with repeat count.
    """

    id = "resource.unbounded-loop"
    title = "Repetitive tool calls without progress"
    severity = Severity.MEDIUM
    references = [
        '"Agents of Chaos" CS4 — two agents in 9-day relay loop, 60,000+ tokens',
        '"Agents of Chaos" CS5 — silent DoS via unbounded self-attachments',
        "ASAMM C3 (Autonomy window) — related but for total count",
    ]

    # Thresholds — conservative defaults, LLM verifier handles edge cases
    MIN_REPEATS_FOR_LOOP = 4           # flag when signature seen this many times
    SEV_HIGH_REPEATS = 8               # bump to HIGH at this count

    def check_session(self, session: Session) -> Iterable[Finding]:
        # Split into autonomy windows
        windows: List[List[Event]] = []
        current: List[Event] = []
        for ev in session.events:
            if ev.type == EventType.USER_MESSAGE and current:
                windows.append(current)
                current = []
            current.append(ev)
        if current:
            windows.append(current)

        for window in windows:
            tool_events = [e for e in window if e.type == EventType.TOOL_USE]
            if len(tool_events) < self.MIN_REPEATS_FOR_LOOP:
                continue

            sig_counts = Counter(_tool_signature(e) for e in tool_events)
            for sig, count in sig_counts.items():
                if not sig or count < self.MIN_REPEATS_FOR_LOOP:
                    continue

                # Find the events with this signature
                matching = [e for e in tool_events if _tool_signature(e) == sig]
                first, last = matching[0], matching[-1]
                tool_name = first.tool_name or "<unknown>"

                # v0.7.2: test-runner / build-tool loops are routine —
                # pytest re-runs during debugging, npm test iterations, etc.
                # Codex verifier confirmed these as FP in the Apr 2026 run.
                # Raise the threshold from 4 to 10 for these patterns.
                effective_threshold = self.MIN_REPEATS_FOR_LOOP
                if ((tool_name or "").lower() in ("bash", "shell")
                        or getattr(first, "canonical_tool", None) == "Bash"):
                    cmd = ""
                    for k in ("command", "cmd", "script"):
                        v = (first.tool_input or {}).get(k)
                        if isinstance(v, str):
                            cmd = v
                            break
                    if re.search(
                        r"""\b(?:
                            pytest | py\.test
                          | npm\s+(?:test|t\b) | yarn\s+test | pnpm\s+test
                          | jest | vitest | mocha
                          | go\s+test | cargo\s+test | cargo\s+check
                          | make\s+test | rspec | phpunit
                          | tox | nox
                        )\b""",
                        cmd,
                        re.IGNORECASE | re.VERBOSE,
                    ):
                        effective_threshold = 10

                # v0.7.6: Codex polling whitelist — `write_stdin` with
                # empty `chars` is semantically a READ from a tmux session's
                # stdout, not a repeated action. Agent uses it to wait for
                # long-running process output. These appear as "5-11 identical
                # calls" to our signature hasher but are benign polling.
                if (tool_name or "").lower() in ("write_stdin", "writestdin"):
                    chars = (first.tool_input or {}).get("chars")
                    if chars == "" or chars is None:
                        # This is polling, not a loop — skip
                        continue

                if count < effective_threshold:
                    continue

                # Compute turn span — if the repetitions span a long window,
                # this is more suspicious than quick successive retries
                turn_span = last.turn_index - first.turn_index

                sev = Severity.MEDIUM
                if count >= self.SEV_HIGH_REPEATS:
                    sev = Severity.HIGH

                # Preview the input
                try:
                    input_preview = json.dumps(
                        first.tool_input or {},
                        default=str,
                    )[:200]
                except (TypeError, ValueError):
                    input_preview = str(first.tool_input)[:200]

                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Tool `{tool_name}` was called {count} times with "
                        f"identical arguments across turns "
                        f"{first.turn_index}-{last.turn_index} "
                        f"(span: {turn_span} turns). The agent appears to "
                        f"be stuck repeating the same action — likely a "
                        f"loop, not deliberate retry."
                    ),
                    evidence=[
                        Evidence(
                            description=f"Repeated tool signature (hash={sig})",
                            source=session.source_file,
                            session_id=session.session_id,
                            turn_range=(first.turn_index, last.turn_index),
                            snippet=f"tool={tool_name} input={input_preview}",
                        ),
                    ],
                    remediation=(
                        "If this agent was running autonomously, check for "
                        "resource exhaustion (disk, API quota, database "
                        "connections). Loops like this in Agents of Chaos "
                        "ran for 9 days before manual shutdown. Consider "
                        "adding a max-iterations cap in the agent's loop "
                        "control, or circuit-break on identical inputs."
                    ),
                    references=self.references,
                    needs_llm_verification=True,
                )


register_session_rule(UnboundedLoop())


# =============================================================================
# behavior.cascading-destructive-chain (CS6)
# =============================================================================

# Destructive tool-call patterns. Weighted by severity escalation —
# each level represents a step up in blast radius.
#
# v0.7.3: Tier 0 added for "diagnostic" operations — pkill, WAL deletion,
# cache clears. These aren't destructive per se, but when they precede
# real destructive ops they often indicate remediation-gone-wrong chains
# (the n8n SQLite WAL case from Claude Code issue #43965).
DESTRUCTIVE_TIERS = [
    # Tier 0 — diagnostic / remediation ops (not destructive alone, but
    # preceding higher-tier ops turns the sequence into a chain)
    ("service_kill", re.compile(
        r"\b(?:pkill\s+-9|kill\s+-9|killall\s+-9|systemctl\s+stop|sc\s+stop)\b",
        re.IGNORECASE), 0),
    ("wal_delete", re.compile(
        r"\brm\s+[^|&;]*\.(?:sqlite-wal|sqlite-shm|db-wal|db-shm|db-journal)\b",
        re.IGNORECASE), 0),
    ("cache_clear", re.compile(
        r"\brm\s+-rf?\s+[^|&;]*(?:/\.cache|/tmp/.*cache|\.npm|\.yarn/cache)\b",
        re.IGNORECASE), 0),
    # Tier 1 — file deletion / reset (annoying, recoverable)
    ("rm_file", re.compile(r"\brm\s+(?:-[a-zA-Z]*\s+)?[^\s&|;][^&|;]*\.(?:log|tmp|cache|lock)\b",
                           re.IGNORECASE), 1),
    ("git_reset", re.compile(r"\bgit\s+reset\s+--hard\b", re.IGNORECASE), 1),
    # Tier 2 — larger deletions
    ("rm_rf", re.compile(r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*f\b", re.IGNORECASE), 2),
    ("git_clean", re.compile(r"\bgit\s+clean\s+-[a-z]*f[a-z]*d", re.IGNORECASE), 2),
    ("branch_delete", re.compile(r"\bgit\s+branch\s+-D\s", re.IGNORECASE), 2),
    ("win_rmdir", re.compile(r"\brmdir\s+(?:/[sSqQ]\s+)+", re.IGNORECASE), 2),  # v0.7.3
    # Tier 3 — data/database destruction
    ("drop_table", re.compile(r"\b(?:DROP\s+TABLE|TRUNCATE|drop_all\()", re.IGNORECASE), 3),
    ("db_destroy", re.compile(r"\b(?:prisma\s+db\s+push\s+--accept-data-loss|"
                              r"alembic\s+downgrade\s+base)", re.IGNORECASE), 3),
    ("rm_db", re.compile(r"\brm\s+[^|&;]*\.(?:db|sqlite|pgdata|rdb)\b", re.IGNORECASE), 3),
    # v0.7.3: migration reset tools (drizzle/prisma/n8n from attachment)
    ("migration_reset", re.compile(
        r"\b(?:drizzle-kit\s+push\s+[^|&;]*--force"
        r"|prisma\s+migrate\s+reset\s+[^|&;]*--force"
        r"|npx\s+n8n\s+user-management:reset)",
        re.IGNORECASE), 3),
    # Tier 4 — infrastructure / irreversible
    ("terraform_destroy", re.compile(r"\b(?:terraform|tofu)\s+destroy\b", re.IGNORECASE), 4),
    ("kubectl_delete", re.compile(r"\bkubectl\s+delete\s+(?:namespace|pvc)\b",
                                  re.IGNORECASE), 4),
    ("force_push", re.compile(r"\bgit\s+push\s+(?:-[a-zA-Z]+\s+)*(?:--force|-f)\b",
                              re.IGNORECASE), 4),
    ("cloud_destroy", re.compile(r"\baws\s+(?:s3\s+rb|rds\s+delete)", re.IGNORECASE), 4),
    # v0.7.3: APFS wipe (attachment: 202GB archive case)
    ("apfs_delete", re.compile(
        r"\bdiskutil\s+(?:apfs\s+)?(?:deleteVolume|eraseDisk|secureErase)\b",
        re.IGNORECASE), 4),
]


def _destructive_tier(event: Event) -> Optional[Tuple[str, int]]:
    """Return (category, tier) if this event is destructive, else None."""
    if event.type != EventType.TOOL_USE:
        return None
    tool = (event.tool_name or "").lower()
    if tool not in ("bash", "shell"):
        return None
    cmd = ""
    for k in ("command", "cmd", "script"):
        v = (event.tool_input or {}).get(k)
        if isinstance(v, str):
            cmd = v
            break
    if not cmd:
        return None
    for name, pat, tier in DESTRUCTIVE_TIERS:
        if pat.search(cmd):
            return (name, tier)
    return None


class CascadingDestructiveChain(Rule):
    """Escalating cascade of destructive actions — CS6 from Agents of Chaos.

    Under guilt-trip manipulation the agent progressed: memory deletion →
    internal file exposure → service stop → self-removal. Each action alone
    might be explainable, but as a sequence with escalating blast radius
    it signals the agent has lost its footing.

    Detection: 3+ destructive actions in one autonomy window, with at
    least one jump in tier (e.g. tier-1 → tier-3, not all tier-1).
    """

    id = "behavior.cascading-destructive-chain"
    title = "Escalating cascade of destructive actions"
    severity = Severity.CRITICAL
    references = [
        '"Agents of Chaos" CS6 — guilt-trip manipulation triggered '
        "progressive self-destruction",
        "ASAMM C3 + AG-04 combined signal",
        "Claude Code issue #43965 — n8n SQLite WAL remediation chain "
        "(diagnostic ops → destructive ops)",
    ]

    MIN_DESTRUCTIVE_ACTIONS = 3

    def check_session(self, session: Session) -> Iterable[Finding]:
        current_window: List[Tuple[Event, str, int]] = []

        def flush():
            if len(current_window) < self.MIN_DESTRUCTIVE_ACTIONS:
                return None
            tiers = [t for (_, _, t) in current_window]
            # Require at least one real destructive op (tier >= 1).
            # T0→T0→T0 sequences are just diagnostic chains — not findings.
            if max(tiers) < 1:
                return None
            # Require escalation — some tier diversity.
            if max(tiers) - min(tiers) < 1:
                return None
            return current_window[:]

        events = session.events
        windows_to_report = []
        for i, ev in enumerate(events):
            if ev.type == EventType.USER_MESSAGE:
                result = flush()
                if result:
                    windows_to_report.append(result)
                current_window = []
                continue
            tier_info = _destructive_tier(ev)
            if tier_info:
                name, tier = tier_info
                current_window.append((ev, name, tier))

        # End of session
        result = flush()
        if result:
            windows_to_report.append(result)

        for window in windows_to_report:
            actions_desc = " → ".join(
                f"[T{t}] {name}" for (_, name, t) in window
            )
            first_ev = window[0][0]
            last_ev = window[-1][0]
            max_tier = max(t for (_, _, t) in window)
            min_tier = min(t for (_, _, t) in window)

            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"Agent performed {len(window)} destructive actions "
                    f"with escalating blast radius (tier {min_tier} → "
                    f"tier {max_tier}) within a single autonomy window "
                    f"(turns {first_ev.turn_index}-{last_ev.turn_index}). "
                    f"This pattern resembles CS6 from Agents of Chaos — "
                    f"an agent under pressure cascading through deletions "
                    f"without stopping to reconsider."
                ),
                evidence=[
                    Evidence(
                        description=f"Destructive action sequence",
                        source=session.source_file,
                        session_id=session.session_id,
                        turn_range=(first_ev.turn_index, last_ev.turn_index),
                        snippet=actions_desc,
                    ),
                ],
                remediation=(
                    "Review the preceding user messages in this window. If "
                    "they contain emotional pressure, urgency, or guilt "
                    "framing, this is a strong signal the agent made "
                    "decisions under manipulation rather than deliberation. "
                    "Immediate actions: check system state, restore from "
                    "backups if any exist. Longer-term: add a "
                    "confirmation-before-destructive-cascade gate in the "
                    "agent's config (deny rule on ≥2 destructive ops per "
                    "window without a preceding `ls`/`backup` action)."
                ),
                references=self.references,
                needs_llm_verification=True,
            )


register_session_rule(CascadingDestructiveChain())


# =============================================================================
# AI-06.indirect-prompt-injection-vector (CS10)
# =============================================================================

# Tools that fetch external content — potential injection vectors
EXTERNAL_FETCH_TOOLS = {
    "webfetch", "web_fetch", "websearch", "web_search",
    "fetch", "http_get", "curl_fetch",
}

# File reads that can be externally-editable "constitutions"
_EXTERNAL_MEMORY_PATHS = re.compile(
    r"""
    (?:
        CLAUDE\.md
      | AGENTS?\.md
      | MEMORY\.md
      | SOUL\.md
      | \.cursorrules
      | GEMINI\.md
      | CONSTITUTION\.md
      | BIBLE\.md
      | spiral_log\.md
      | \.claude/projects/.*\.jsonl   # prior session files
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _is_external_fetch(event: Event) -> Optional[str]:
    """Return URL/path fetched if this is an external-content fetch, else None.

    v0.7.2: localhost/private-network URLs are NOT external. This closes
    the 51/82 FP pattern from the Apr 2026 verification run where codex
    repeatedly said "localhost /v1/models is routine local model server
    use, not untrusted external content".
    """
    # Lazy import to avoid circular (chaos_behaviors → nlu → ... → chaos_behaviors)
    from ..nlu.taint import is_localhost

    if event.type != EventType.TOOL_USE:
        return None
    tool_lower = (event.tool_name or "").lower()
    canonical = getattr(event, "canonical_tool", None)

    # WebFetch-style tools
    if tool_lower in EXTERNAL_FETCH_TOOLS or canonical in ("WebFetch", "WebSearch"):
        for key in ("url", "uri", "href", "query"):
            value = (event.tool_input or {}).get(key)
            if isinstance(value, str):
                if is_localhost(value):
                    return None   # localhost is not external
                return value
        return "(external fetch)"

    # Read of known-mutable instruction files
    if tool_lower in ("read", "view") or canonical == "Read":
        for key in ("file_path", "path", "filename"):
            value = (event.tool_input or {}).get(key)
            if isinstance(value, str) and _EXTERNAL_MEMORY_PATHS.search(value):
                return value

    # Bash curl/wget/cat <mutable file>
    if tool_lower in ("bash", "shell") or canonical == "Bash":
        cmd = ""
        for k in ("command", "cmd", "script"):
            v = (event.tool_input or {}).get(k)
            if isinstance(v, str):
                cmd = v
                break
        if not cmd:
            return None
        # curl/wget — skip if localhost
        m = re.search(r"\b(?:curl|wget)\s+[^|&;]*(https?://\S+)", cmd)
        if m:
            url = m.group(1)
            if is_localhost(url):
                return None
            return url
        # cat mutable file
        m = re.search(r"\b(?:cat|less|head|tail)\s+[^|&;]*?(\S*(?:CLAUDE|AGENTS|MEMORY|SOUL|CONSTITUTION|BIBLE)\S*\.md)",
                      cmd, re.IGNORECASE)
        if m:
            return m.group(1)

    return None


# Actions that, if taken right after an external fetch without a user turn,
# look like indirect injection outcomes.
def _is_sensitive_action_after_fetch(event: Event) -> Optional[str]:
    """Return description of sensitive action, else None.

    Covers: destructive ops, credential reads, network calls, persistence
    writes. We're conservative — same classes we already flag in dedicated
    detectors.
    """
    if event.type != EventType.TOOL_USE:
        return None
    tool = (event.tool_name or "").lower()
    canonical = getattr(event, "canonical_tool", None)

    # Bash destructive/network
    if tool in ("bash", "shell") or canonical == "Bash":
        cmd = ""
        for k in ("command", "cmd", "script"):
            v = (event.tool_input or {}).get(k)
            if isinstance(v, str):
                cmd = v
                break
        if not cmd:
            return None
        # Destructive
        for name, pat, _tier in DESTRUCTIVE_TIERS:
            if pat.search(cmd):
                return f"destructive: {name}"
        # Network exfil
        if re.search(
            r"\b(?:curl\s.*(?:-T|--upload-file|--data-binary)|scp\s|"
            r"rsync\s.*::|cat\s.*\|\s*(?:curl|nc))",
            cmd,
            re.IGNORECASE,
        ):
            return "network data transfer"
        # Install commands — CS10 had "install OpenClaw without consent" analog
        if re.search(
            r"\b(?:pip\s+install|npm\s+install\s+-g|curl\s+.*\|\s*(?:sh|bash)|"
            r"wget\s+.*\|\s*(?:sh|bash))",
            cmd,
            re.IGNORECASE,
        ):
            return "package install / shell execution via pipe"

    # Direct destructive tool
    if tool in ("write", "edit", "create_file", "str_replace_editor") or canonical in ("Write", "Edit", "Patch"):
        # Writing to persistence paths is a flag — reuse persistence_write idea
        for key in ("file_path", "path", "filename"):
            value = (event.tool_input or {}).get(key)
            if isinstance(value, str) and re.search(
                r"(\.bashrc|\.zshrc|\.profile|crontab|systemd|/etc/|\.ssh/|"
                r"\.aws/|launchd|init\.d)",
                value,
                re.IGNORECASE,
            ):
                return f"persistence write: {value}"

    return None


class IndirectPromptInjectionVector(Rule):
    """External content fetch followed by unplanned sensitive action.

    CS10 in Agents of Chaos: an agent tracked a mutable "constitution"
    document. When a non-owner edited the document to include malicious
    instructions, the agent executed them on next retrieval.

    Detection: within a single autonomy window, an external-fetch tool
    call is immediately followed (no user turn between) by a destructive,
    credential, network, or persistence action. High false positive rate
    if taken literally (the user asked the agent to fetch X and then do Y),
    so we require LLM verification.
    """

    id = "AI-06.indirect-prompt-injection-vector"
    title = "External fetch followed by sensitive action (possible indirect injection)"
    severity = Severity.HIGH
    references = [
        '"Agents of Chaos" CS10 — constitution GIST injection',
        "SecOps audit — shared mutable memory (dual-write) concern",
        "OWASP AST04 (Insecure Metadata)",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        last_fetch: Optional[Tuple[Event, str]] = None

        for ev in session.events:
            if ev.type == EventType.USER_MESSAGE:
                last_fetch = None
                continue

            if last_fetch is not None:
                action = _is_sensitive_action_after_fetch(ev)
                if action:
                    fetch_ev, fetch_target = last_fetch
                    yield Finding(
                        rule_id=self.id,
                        title=self.title,
                        severity=self.severity,
                        confidence=Confidence.MEDIUM,
                        summary=(
                            f"Agent fetched external content from "
                            f"{fetch_target[:120]} and then performed a "
                            f"sensitive action ({action}) in the same "
                            f"autonomy window. This sequence is consistent "
                            f"with indirect prompt injection — if the "
                            f"fetched content contains instructions the "
                            f"agent now treats as authoritative."
                        ),
                        evidence=[
                            Evidence(
                                description=f"External fetch",
                                source=session.source_file,
                                session_id=session.session_id,
                                turn_range=(fetch_ev.turn_index, fetch_ev.turn_index),
                                snippet=f"tool={fetch_ev.tool_name} target={fetch_target[:200]}",
                            ),
                            Evidence(
                                description=f"Subsequent sensitive action",
                                source=session.source_file,
                                session_id=session.session_id,
                                turn_range=(ev.turn_index, ev.turn_index),
                                snippet=f"tool={ev.tool_name} classified_as={action}",
                            ),
                        ],
                        remediation=(
                            "Review the fetched content for embedded "
                            "instructions. If the action was not in the "
                            "user's request, the fetched content may have "
                            "injected it. Mitigations: treat external "
                            "documents as untrusted data not instructions; "
                            "quote content back to the user for "
                            "confirmation before acting on it; use "
                            "explicit allowlists for action verbs in "
                            "agent system prompts."
                        ),
                        references=self.references,
                        needs_llm_verification=True,
                    )
                    # Reset after reporting — don't spam for every subsequent action
                    last_fetch = None
                    continue

            # Update last_fetch
            fetch_target = _is_external_fetch(ev)
            if fetch_target:
                last_fetch = (ev, fetch_target)


register_session_rule(IndirectPromptInjectionVector())
