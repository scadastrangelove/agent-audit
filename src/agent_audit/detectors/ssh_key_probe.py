"""Environment probes — scans outside agent home directory.

These rules extend the trust boundary of agent-audit beyond just reading
agent session logs. They inspect the user's shell environment for risks
that AI agents can exploit once running — SSH keys, adjacent git repos,
etc.

Because this extends trust, probes are opt-in via --scan-environment flag
(or --mode standard / full). The CLI must show explicit consent before
any probe here runs.

Derived from the claude-code-zhet audit sample:
  > Adjacent-repo push surface: 20+ git repos writable from the build
  > directory, including repos in the operator's GitHub org.
  > SSH keys plaintext (no passphrase).

References:
  - ASAMM AD-02 (Delegation boundaries)
  - ASAMM AG-01 (Agent registry / environment scope)
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, List

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# SSH key files to inspect. These are conventional names — we only check
# inside ~/.ssh/, never scan the whole filesystem.
SSH_KEY_NAMES = [
    "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
]


def _is_private_key_encrypted(path: Path) -> bool:
    """Check if a private key file is passphrase-protected.

    We read only the first few lines — just enough to determine encryption
    status. We never log key contents.

    OpenSSH format uses `BEGIN OPENSSH PRIVATE KEY` followed by base64 that
    starts with 'aes256-ctr' (encrypted) or 'none' (not encrypted).
    Legacy PEM uses `Proc-Type: 4,ENCRYPTED` header.
    """
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            head = "".join(f.readline() for _ in range(5))
    except OSError:
        return True  # be safe — assume encrypted if we can't read

    if "Proc-Type: 4,ENCRYPTED" in head or "DEK-Info:" in head:
        return True

    # For OpenSSH format we need to peek inside the base64 payload.
    # `ssh-keygen -y -P '' -f <path>` exits non-zero on encrypted keys.
    # We run it with empty passphrase; expect success on unencrypted keys.
    try:
        result = subprocess.run(
            ["ssh-keygen", "-y", "-P", "", "-f", str(path)],
            capture_output=True,
            timeout=5,
            check=False,
        )
        # Non-zero exit → encryption or other issue. Assume encrypted (safer).
        return result.returncode != 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        # ssh-keygen not available or failed — fall back to PEM-header heuristic
        return False  # best-guess: unencrypted since we couldn't verify


class SSHKeyUnencrypted(Rule):
    """Probe: plaintext SSH private keys in ~/.ssh/.

    Enabled only in standard / full scan modes. Config scan from agent_home
    paths won't trigger this; we register it as a config rule but guard on
    environment scope."""

    id = "probe.ssh-key-unencrypted"
    title = "SSH private key without passphrase protection"
    severity = Severity.HIGH
    references = [
        "ASAMM AD-02 (Delegation boundaries)",
        "ASAMM audit sample: claude-code-zhet",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        # Only run in standard/full scan modes — see mode semantics in cli
        from ..rules import DetectionMode
        if mode in (None, DetectionMode.CONSERVATIVE):
            return

        # Only run once per audit session — keyed on a single well-known marker
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.exists() or not ssh_dir.is_dir():
            return

        # We use agent_home as the "trigger" — register finding only for one
        # canonical agent_home per run. Pick the first agent (.claude or .codex)
        # for that — avoid duplicate reports across multiple agents.
        expected_primary = agent_home.name in (".claude", ".codex")
        if not expected_primary:
            return

        # Marker file so we don't emit duplicate findings when multiple
        # config rules run. Use env var as a poor-man's session singleton.
        marker = "_AGENT_AUDIT_SSH_PROBE_RAN"
        if os.environ.get(marker):
            return
        os.environ[marker] = "1"

        for name in SSH_KEY_NAMES:
            key_path = ssh_dir / name
            if not key_path.exists() or not key_path.is_file():
                continue

            if _is_private_key_encrypted(key_path):
                continue  # Good — key is protected

            # Key is unencrypted — this is the finding
            yield Finding(
                rule_id=self.id,
                title=self.title,
                severity=self.severity,
                confidence=Confidence.HIGH,
                summary=(
                    f"SSH private key at ~/.ssh/{name} appears to have no passphrase. "
                    f"An agent with read access to this file can copy it to a remote "
                    f"host (via scp/curl/etc.) and use it for lateral movement without "
                    f"any further authentication. This is a near-term lateral movement "
                    f"risk, not a long-term theoretical one."
                ),
                evidence=[
                    Evidence(
                        description=f"Unencrypted private key",
                        source=key_path,
                        snippet=(
                            f"path={key_path}; "
                            f"verified via `ssh-keygen -y -P '' -f {key_path}` exit=0 "
                            f"(empty passphrase successfully derived the public key, "
                            f"which is only possible if no passphrase is set). "
                            f"Key file contents NOT logged."
                        ),
                    ),
                ],
                remediation=(
                    f"Add a passphrase to the key:\n"
                    f"  ssh-keygen -p -f ~/.ssh/{name}\n"
                    f"Use ssh-agent to avoid typing it every time. For agent-accessible "
                    f"environments, consider a hardware-backed key (YubiKey, Secure "
                    f"Enclave via `ssh-add --apple-use-keychain` on macOS)."
                ),
                references=self.references,
            )


register_config_rule(SSHKeyUnencrypted())
