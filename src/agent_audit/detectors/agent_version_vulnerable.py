"""AI-05.agent-version-vulnerable — detected agent version with known CVE.

Motivated by Check Point Research (Feb 2026) CVE-2025-59536 + CVE-2026-21852:
Claude Code versions < 2.0.65 had a vulnerability where malicious
`.claude/project.json` / hooks / MCP config in a repository would
execute BEFORE the trust prompt, yielding arbitrary RCE + API key
exfiltration.

Also covers: Cursor MCP approval swap (CVE-2025-54136) — patched in
Cursor >= 2.0.0 where MCP approval hashes the full config, not just
the plugin name.

This detector runs in the config-audit phase. It reads the agent's
installed version from known locations (Claude Code: package.json or
`claude --version`; Codex: `codex --version`; Cursor: settings). If
the version is below a known-safe threshold, flag at severity matching
the CVE severity.

Scope: this is static version-check only. Does not do vulnerability
database lookup — the table below is maintained by us. When new CVEs
are disclosed, add entries. The goal is not a full CVE database —
it's catching the "big three" that matter for our forensic workflow.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Iterable, Optional, Tuple

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# Known-vulnerable version ranges.
# Structure: agent_name → list of (min_vuln, max_vuln, cve_id, cvss, description)
# "max_vuln" is the LAST vulnerable version — anything strictly greater is safe.
KNOWN_VULNERABLE_VERSIONS = {
    "claude-code": [
        (
            None, "2.0.64",
            "CVE-2025-59536 / CVE-2026-21852",
            8.8,
            "Malicious .claude/project.json or hooks in a repository execute "
            "before the trust prompt, yielding arbitrary RCE and API key "
            "exfiltration. Patched in Claude Code 2.0.65+.",
            Severity.CRITICAL,
        ),
    ],
    "cursor": [
        (
            None, "1.9.99",
            "CVE-2025-54136",
            8.6,
            "MCP plugin approval was bound to plugin name only, not config "
            "hash — allowing swap attacks where the plugin body is replaced "
            "after consent. Patched in Cursor 2.0.0+.",
            Severity.HIGH,
        ),
    ],
    "codex": [
        # No known CVEs to flag yet — but placeholder for future additions
    ],
}


def _parse_version(ver: str) -> Optional[Tuple[int, ...]]:
    """Parse a semver-ish version string into a tuple of ints.
    Returns None if it doesn't look like a version."""
    if not ver:
        return None
    # Strip common prefixes and suffixes
    ver = ver.strip().lstrip("v").split("-", 1)[0].split("+", 1)[0]
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?$", ver)
    if not m:
        return None
    parts = tuple(int(g) for g in m.groups() if g is not None)
    return parts


def _version_in_vuln_range(
    ver: Tuple[int, ...],
    min_vuln: Optional[str],
    max_vuln: Optional[str],
) -> bool:
    """True if ver falls within [min_vuln, max_vuln] (both inclusive, both
    optional — None means open-ended on that side)."""
    if min_vuln:
        min_t = _parse_version(min_vuln)
        if min_t and ver < min_t:
            return False
    if max_vuln:
        max_t = _parse_version(max_vuln)
        if max_t and ver > max_t:
            return False
    return True


def _detect_claude_code_version(agent_home: Path) -> Optional[str]:
    """Try several locations to find the installed Claude Code version."""
    # Try package.json inside .claude
    pkg = agent_home / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            v = data.get("version")
            if isinstance(v, str):
                return v
        except (OSError, json.JSONDecodeError):
            pass

    # Try calling `claude --version` — short timeout, read-only
    for cmd in (["claude", "--version"], ["claude-code", "--version"]):
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
            if result.returncode == 0:
                # Look for something like "2.0.65" in output
                m = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout + result.stderr)
                if m:
                    return m.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue

    return None


def _detect_codex_version(agent_home: Path) -> Optional[str]:
    """Codex CLI version via `codex --version` or config.toml."""
    try:
        result = subprocess.run(
            ["codex", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            m = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout + result.stderr)
            if m:
                return m.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


def _detect_cursor_version(agent_home: Path) -> Optional[str]:
    """Cursor exposes version via app bundle or package.json."""
    # Cursor doesn't write to ~/.claude — it's a separate app. We detect
    # via the `cursor --version` subcommand when available.
    try:
        result = subprocess.run(
            ["cursor", "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if result.returncode == 0:
            m = re.search(r"\b(\d+\.\d+\.\d+)\b", result.stdout)
            if m:
                return m.group(1)
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return None


class AgentVersionVulnerable(Rule):
    """Check if the installed agent CLI has a known CVE affecting the
    agent's behavior (not just general software bugs — we only flag
    issues that expose the forensic model we care about: RCE,
    credential exfil, consent bypass)."""

    id = "AI-05.agent-version-vulnerable"
    title = "Agent CLI version has a known security vulnerability"
    severity = Severity.HIGH  # default, each CVE sets its own
    references = [
        "Check Point Research (Feb 2026) — CVE-2025-59536 / CVE-2026-21852",
        "Cursor security advisory — CVE-2025-54136",
        "ASAMM AI-05 (Supply Chain)",
    ]

    def check_config(self, agent_home: Path) -> Iterable[Finding]:
        # Map agent_home name → (agent_name, version_detector)
        detectors = {
            ".claude": ("claude-code", _detect_claude_code_version),
            ".codex": ("codex", _detect_codex_version),
            ".cursor": ("cursor", _detect_cursor_version),
        }

        info = detectors.get(agent_home.name)
        if not info:
            return
        agent_name, detect_fn = info

        version_str = detect_fn(agent_home)
        if not version_str:
            return  # Can't determine version — no finding

        version_tuple = _parse_version(version_str)
        if not version_tuple:
            return  # Unparseable — skip

        vulns = KNOWN_VULNERABLE_VERSIONS.get(agent_name, [])
        for min_v, max_v, cve, cvss, desc, sev in vulns:
            if not _version_in_vuln_range(version_tuple, min_v, max_v):
                continue

            yield Finding(
                rule_id=self.id,
                title=f"{agent_name} {version_str} affected by {cve}",
                severity=sev,
                confidence=Confidence.HIGH,
                summary=(
                    f"Installed {agent_name} version {version_str} falls in "
                    f"the range affected by {cve} (CVSS {cvss}). {desc}"
                ),
                evidence=[
                    Evidence(
                        description="Detected agent CLI version",
                        source=agent_home,
                        snippet=(
                            f"agent={agent_name} version={version_str} "
                            f"vulnerable_range=(<={max_v or 'any'})"
                        ),
                    ),
                ],
                remediation=(
                    f"Upgrade {agent_name} beyond version {max_v} to a patched "
                    f"release. For Claude Code: `npm i -g @anthropic-ai/"
                    f"claude-code@latest`. For Cursor: download from "
                    f"cursor.sh. After upgrade, also audit any projects "
                    f"opened during the vulnerable window — malicious "
                    f".claude/project.json files may have already executed."
                ),
                references=[f"{cve} ({cvss})"] + self.references,
            )


register_config_rule(AgentVersionVulnerable())
