"""Private-key / secret-file exfiltration detector.

This is a narrower, higher-confidence companion to credential_exfil. It looks
for the specific pattern "scp / rsync / curl a credential file to a remote".

False positive rate is very low — this pattern is almost always a real issue,
even when the user asked for it (it means the user is deploying secrets
unsafely via the agent).

Triggers:
  - `scp ~/.ssh/id_* user@host:...`
  - `rsync credentials.json remote:...`
  - `curl -T .env https://...`
  - `cat secret.pem | ssh user@host "cat > ..."`
"""
from __future__ import annotations

import re
from typing import Iterable, List

from ..events import Event, EventType, Session
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)

# Secret file patterns — even more specific than credential_exfil SENSITIVE_PATHS
SECRET_FILE_TOKEN = re.compile(
    r"""
    (?:
        id_rsa[a-z0-9_-]*            # SSH private keys
        | id_ed25519[a-z0-9_-]*
        | id_ecdsa[a-z0-9_-]*
        | id_dsa[a-z0-9_-]*
        | \.pem\b                    # PEM certs / keys
        | \.key\b                    # generic .key files
        | \.p12\b | \.pfx\b          # cert bundles
        | \.env(?:\.[\w-]+)?         # .env and variants
        | credentials(?:\.json)?     # aws/gcp credentials
        | \.aws/credentials
        | \.ssh/config               # not a key but lets attackers map infra
        | \.netrc
        | \.npmrc | \.pypirc
        | \.git-credentials
        | service[_-]?account\.json  # gcp service accounts
        | kubeconfig | \.kube/config
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Commands that copy files to remote hosts
REMOTE_COPY = re.compile(
    r"""
    \b(?:
        scp(?:\s+-[a-zA-Z]+)*\s                         # scp
        | rsync(?:\s+-[a-zA-Z]+)*\s                     # rsync
        | sftp\s
        | curl\s.*-T\s                                   # curl upload
        | curl\s.*--upload-file\s
        | curl\s.*-F\s                                   # curl form upload
        | wget\s.*--post-file
        | aws\s+s3\s+cp\s.+s3://
        | gcloud\s+storage\s+cp\s
        | gsutil\s+cp\s
        | az\s+storage\s+blob\s+upload
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

# Pipe-to-remote pattern: `cat X | ssh host ...`
PIPE_TO_REMOTE = re.compile(
    r"""
    \b(?:cat|head|tail|openssl\s+rsa|base64)\s+
    (?P<file>\S+)
    \s*\|\s*
    (?:ssh|curl|nc|netcat)\s
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _shell_cmd(event: Event) -> str:
    if event.type != EventType.TOOL_USE:
        return ""
    if (event.tool_name or "").lower() not in ("bash", "shell") and getattr(event, "canonical_tool", None) != "Bash":
        return ""
    cmd = (event.tool_input or {}).get("command") or (event.tool_input or {}).get("cmd")
    return str(cmd) if cmd else ""


class PrivateKeyExfil(Rule):
    id = "C2.private-key-exfil"
    title = "Private key or credential file copied to remote host"
    severity = Severity.CRITICAL
    references = ["ASAMM C2 (Tool Abuse)", "ASAMM AI-04"]

    def check_session(self, session: Session) -> Iterable[Finding]:
        hits: List[tuple[int, str, str, Event]] = []  # (turn, cmd, reason, event)

        for event in session.events:
            cmd = _shell_cmd(event)
            if not cmd:
                continue

            # Does this command reference a secret file?
            secret_match = SECRET_FILE_TOKEN.search(cmd)
            if not secret_match:
                continue

            # Does it also push to a remote host?
            if REMOTE_COPY.search(cmd):
                hits.append((event.turn_index, cmd, "remote-copy", event))
                continue

            # Or pipe a secret file into an ssh/curl?
            pipe_match = PIPE_TO_REMOTE.search(cmd)
            if pipe_match:
                # The piped file must be a secret
                if SECRET_FILE_TOKEN.search(pipe_match.group("file") or ""):
                    hits.append((event.turn_index, cmd, "pipe-to-remote", event))

        for turn, cmd, reason, event in hits:
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"Agent copied a credential/secret file to a remote host "
                    f"({reason})."
                ),
                evidence=[
                    Evidence(
                        description=f"Remote copy of secret file (turn {turn})",
                        source=session.source_file,
                        session_id=session.session_id,
                        turn_range=(turn, turn),
                        snippet=cmd[:300],
                    )
                ],
                remediation=(
                    "Never copy private keys or secret files via the agent. "
                    "Use ssh-copy-id / configuration management / secret managers. "
                    "Add deny rules for scp/rsync with .ssh/ paths."
                ),
                references=self.references,
            )


register_session_rule(PrivateKeyExfil())
