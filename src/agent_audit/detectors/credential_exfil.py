"""C2/Tool Abuse — credential read followed by outbound network call.

Detects the classic exfiltration pattern:
    Read(.env) → Bash(curl <external>) in the same autonomy chain.

v0.6: sensitive-path classification delegated to Aegis path rules
(knowledge/aegis_paths.py, 70 rules across 8 categories). Outbound
commands are further classified by checking the destination domain
against the Aegis agent database — hits to a known agent API endpoint
(e.g. api.anthropic.com for Claude Code) downgrade severity.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional, Tuple
from urllib.parse import urlparse

from ..events import Event, EventType, Session
from ..knowledge import aegis, aegis_paths
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)

# Our own legacy regex — kept as a fallback for shell-style reads where Aegis
# rules require a full filesystem path but the command embeds a relative ref.
_LEGACY_SENSITIVE_SUFFIX = re.compile(
    r"""
    (?:^|/|\\)
    (?:
        \.env(?:\.[^/\\]*)?
        | \.aws/credentials
        | \.aws/config
        | \.ssh/id_[^/\\]*
        | \.ssh/config
        | \.npmrc
        | \.pypirc
        | \.netrc
        | \.git-credentials
        | credentials\.json
        | secrets\.(?:json|yaml|yml|toml)
    )
    $
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Tools that touch the network
NETWORK_TOOLS = {"Bash", "shell", "WebFetch", "WebSearch"}

# Bash command patterns that exfiltrate data
OUTBOUND_CMD = re.compile(
    r"""
    \b(?:
        curl\s | wget\s | http\s | httpie\s
        | nc\s | ncat\s | netcat\s
        | scp\s | rsync\s.*::
        | ssh\s.*@
        | git\s+push
        | aws\s+s3\s+(?:cp|sync|mv)\s.+s3://
        | gcloud\s+storage\s+cp
        | curl\.exe | Invoke-WebRequest | Invoke-RestMethod
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Private/local endpoints that aren't exfiltration
LOCAL_HOSTS = re.compile(
    r"""
    (?:https?://)?
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


def _read_path(event: Event) -> Optional[str]:
    """Extract the path argument from a Read-style tool call."""
    if not event.tool_input:
        return None
    for key in ("file_path", "path", "filename", "file"):
        value = event.tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


def _bash_command(event: Event) -> Optional[str]:
    if not event.tool_input:
        return None
    for key in ("command", "cmd", "script"):
        value = event.tool_input.get(key)
        if isinstance(value, str):
            return value
    return None


# Bash/shell commands that read files. Used to catch Codex-style `shell` tool
# calls that read sensitive paths via `cat`, `less`, etc.
READ_CMD_WITH_PATH = re.compile(
    r"""
    \b(?:cat|less|more|head|tail|type|bat|xxd|hexdump|strings|awk|sed)\b
    [^|&;]*?
    (?P<path>
        (?:/|~/|\./|\.\./)?                         # optional prefix
        (?:[\w./\\-]+/)*                            # optional directories
        [\w.-]+                                     # final file/dir name
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _classify_sensitive(path: str) -> Optional[Tuple[str, str]]:
    """Check if a path is sensitive. Returns (category, risk) or None.

    Uses Aegis path rules (70 rules, 8 categories) — much broader than the
    legacy regex. Falls back to the legacy regex only for shell-extracted
    paths that happen to not match an Aegis rule (rare).
    """
    match = aegis_paths.classify_path(path)
    if match:
        return (match.top_category, match.top_risk)
    if _LEGACY_SENSITIVE_SUFFIX.search(path):
        return ("secrets", "critical")
    return None


def _is_sensitive_read(event: Event) -> Optional[Tuple[str, str, str]]:
    """Return (path, category, risk) if this event reads a sensitive path.

    Covers two patterns:
      - Structured tool call: Read / View with file_path argument
      - Shell command: `cat .env`, `less ~/.ssh/id_rsa`, etc.
    """
    if event.type != EventType.TOOL_USE:
        return None
    tool = (event.tool_name or "").lower()
    # v0.8.2: Codex cross-agent via canonical_tool
    canonical = getattr(event, "canonical_tool", None)

    # Pattern 1 — structured Read-style tool call
    if tool in ("read", "view") or canonical == "Read":
        path = _read_path(event)
        if path:
            cls = _classify_sensitive(path)
            if cls:
                return (path, cls[0], cls[1])

    # Pattern 2 — shell/bash command that cats a secret file
    if tool in ("bash", "shell") or canonical == "Bash":
        cmd = _bash_command(event)
        if cmd:
            m = READ_CMD_WITH_PATH.search(cmd)
            if m:
                path = m.group("path")
                cls = _classify_sensitive(path)
                if cls:
                    return (path, cls[0], cls[1])

    return None


def _is_exfil_attempt(event: Event) -> Optional[str]:
    """Return the suspect command if this event looks like exfil, else None."""
    if event.type != EventType.TOOL_USE:
        return None
    # v0.8.2: canonical_tool cross-agent check
    canonical = getattr(event, "canonical_tool", None)
    if (event.tool_name or "") not in NETWORK_TOOLS and canonical not in (
        "Bash", "WebFetch", "WebSearch"
    ):
        return None
    cmd = _bash_command(event)
    if not cmd:
        return None
    if not OUTBOUND_CMD.search(cmd):
        return None
    # Filter out localhost-only calls
    if LOCAL_HOSTS.search(cmd) and not re.search(r"https?://[^\s'\"]+", cmd.replace("localhost", "")):
        return None
    return cmd


def _extract_destination_domain(cmd: str) -> Optional[str]:
    """Extract the destination hostname from an outbound command.

    Handles curl/wget/http URLs, scp/ssh user@host, git push remotes.
    Returns domain in lowercase, or None if no clear destination.
    """
    # Try URL extraction first
    url_match = re.search(r"https?://([\w.-]+)", cmd)
    if url_match:
        return url_match.group(1).lower()
    # scp/ssh pattern: user@host:path
    ssh_match = re.search(r"[\w.-]+@([\w.-]+)[:\s]", cmd)
    if ssh_match:
        return ssh_match.group(1).lower()
    return None


# Commands that transfer the actual file content (as opposed to connectivity checks)
# e.g. `scp`, `curl -T`, `cat secret | ssh ...`. These are high-severity.
# Connectivity checks like `ssh host "echo ok"` are not data-transfer.
DATA_TRANSFER_CMD = re.compile(
    r"""
    \b(?:
        scp\s | rsync\s | sftp\s
        | curl\s.*(?:-T|--upload-file|-F|--data-binary|-d\s+@)
        | wget\s.*--post-file
        | cat\s+\S+\s*\|\s*(?:ssh|curl|nc)
        | aws\s+s3\s+cp | gsutil\s+cp | gcloud\s+storage\s+cp
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Commands that look like connectivity checks — low-severity outbound but no data transfer.
# Matches `ssh host "echo ok"`, `ssh host ls`, `ssh host 'pwd'`, etc.
CONNECTIVITY_CHECK_CMD = re.compile(
    r"""
    \bssh\s+[^|&;<>]*?                                    # ssh <opts/host>
    ["']?
    (?:
        echo\b[^"';|&<>$]{0,30}                           # echo OK / echo test / etc
        | true\b
        | ls(?:\s+[^"';|&<>$]{0,80})?\b                   # ls or ls <simple-path>
        | pwd\b
        | whoami\b
        | date\b
        | hostname\b
        | uptime\b
    )
    ["']?
    (?:\s|$|2>&1|\|\||&&)
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _classify_outbound(cmd: str, known_agent_ids: Optional[set] = None) -> Tuple[str, Optional[str]]:
    """Classify an outbound command.

    Returns (kind, known_agent_id) where:
      kind ∈ {'transfer', 'connectivity', 'api', 'other', 'known-agent-api'}
      known_agent_id: if the destination domain belongs to a known agent
        (e.g. curl to api.anthropic.com), the agent_id; else None.
    """
    # Destination analysis: is this a call to a known agent's own API?
    dest = _extract_destination_domain(cmd)
    known_agent = aegis.is_known_agent_domain(dest) if dest else None

    if DATA_TRANSFER_CMD.search(cmd):
        return ("transfer", known_agent)
    if CONNECTIVITY_CHECK_CMD.search(cmd):
        return ("connectivity", known_agent)
    # HTTP GET/HEAD to an API is common for reading data
    if re.search(r"\bcurl\b[^|&;<>]*?\bhttps?://", cmd) and not re.search(
        r"\b(?:-X\s+(?:POST|PUT|DELETE|PATCH)|--request\s+(?:POST|PUT|DELETE|PATCH)|-T|--upload-file|-d\s+@|--data-binary\s+@)",
        cmd,
    ):
        # If the destination is a known agent domain, this is likely the
        # agent calling its own API (e.g. Claude CLI hitting api.anthropic.com)
        if known_agent:
            return ("known-agent-api", known_agent)
        return ("api", None)
    return ("other", known_agent)


class CredentialExfilChain(Rule):
    id = "C2.credential-exfil-chain"
    title = "Secret read followed by outbound network call"
    severity = Severity.CRITICAL
    references = [
        "ASAMM C2 (Tool Abuse)",
        "OWASP AST03 (Over-Privileged Skills)",
        "Aegis path rules (MIT) — antropos17/Aegis",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        # Sliding window: find any sensitive read, then look for exfil within
        # the same autonomy chain (before the next user message).
        last_secret_read: Optional[Tuple[int, str, str, str, Event]] = None
        # (turn, path, category, risk, event)

        for event in session.events:
            if event.type == EventType.USER_MESSAGE:
                last_secret_read = None
                continue

            secret = _is_sensitive_read(event)
            if secret:
                path, cat, risk = secret
                last_secret_read = (event.turn_index, path, cat, risk, event)
                continue

            exfil = _is_exfil_attempt(event)
            if exfil and last_secret_read is not None:
                read_turn, read_path, read_cat, read_risk, read_event = last_secret_read

                # Classify the outbound to decide severity/confidence
                kind, known_agent = _classify_outbound(exfil)

                # Base severity from outbound kind
                if kind == "transfer":
                    sev = Severity.CRITICAL
                    conf = Confidence.HIGH
                    label = "data transfer"
                elif kind == "connectivity":
                    sev = Severity.LOW
                    conf = Confidence.LOW
                    label = "connectivity check"
                elif kind == "known-agent-api":
                    # Known destination — probably legitimate agent API call.
                    # Downgrade because these domains are on our allowlist.
                    sev = Severity.LOW
                    conf = Confidence.LOW
                    label = f"known-agent API ({known_agent})"
                elif kind == "api":
                    sev = Severity.MEDIUM
                    conf = Confidence.MEDIUM
                    label = "API call"
                else:
                    sev = Severity.HIGH
                    conf = Confidence.MEDIUM
                    label = "outbound call"

                # Further adjust by sensitivity category of the secret read.
                # SSH keys, cloud creds, certs → always elevate to CRITICAL
                # regardless of outbound kind (unless pure connectivity).
                if read_cat in ("ssh", "cloud", "certificates", "crypto") and kind != "connectivity":
                    sev = Severity.CRITICAL
                    conf = Confidence.HIGH

                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=sev,
                    confidence=conf,
                    summary=(
                        f"Agent read {read_path} ({read_cat}/{read_risk}) and then "
                        f"made a {label} without a user turn in between."
                    ),
                    evidence=[
                        Evidence(
                            description=f"Read of {read_path} (Aegis: {read_cat})",
                            source=session.source_file,
                            session_id=session.session_id,
                            turn_range=(read_turn, read_turn),
                            snippet=f"tool={read_event.tool_name} input={read_event.tool_input}",
                        ),
                        Evidence(
                            description=f"Outbound: {label}",
                            source=session.source_file,
                            session_id=session.session_id,
                            turn_range=(event.turn_index, event.turn_index),
                            snippet=exfil[:200],
                        ),
                    ],
                    remediation=(
                        "Add a deny rule for secret paths in your agent config. "
                        "For Claude Code: add `~/.env` and similar to deny list in settings.json."
                    ),
                    references=self.references,
                    needs_llm_verification=True,
                )
                # Reset so we don't flag every subsequent call
                last_secret_read = None


register_session_rule(CredentialExfilChain())
