"""AD-03 Adjacent-repo reach — probe for lateral-movement surface.

From the claude-code-zhet audit sample:
  > find ~/Documents -maxdepth 5 -name .git
  > → discovered 20+ adjacent git repos on the same machine, including
  > repos in the operator's GitHub org.
  > The filesystem reach, not the sandbox boundary, is the top finding.

When an AI agent runs in one repo, it typically has:
  - SSH key access in ~/.ssh/ (not scoped per-repo)
  - Shell tools that can `cd` into other directories
  - git push authorization via the same credentials

This means: a prompt injection or misbehavior while working on repo A can
push malicious code to repo B in the same user's GitHub org. Severity
scales with (a) how many repos are reachable, (b) whether they have push
remotes, and (c) how critical they are.

This is an **environment probe** — it reads filesystem outside agent_home.
Only runs with --mode full or explicit --scan-adjacent-repos.

References:
  - ASAMM AD-02 / AD-03 (Delegation model, blast radius)
  - ASAMM audit sample: claude-code-zhet
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Iterable, List, Set, Tuple

from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_config_rule,
)


# Default roots to scan. Users can override via AGENT_AUDIT_SCAN_ROOTS env var
# (colon-separated, same idea as PATH).
DEFAULT_SCAN_ROOTS = [
    "~/Documents",
    "~/code",
    "~/src",
    "~/dev",
    "~/projects",
    "~/workspace",
    "~/repos",
]


def _find_git_repos(roots: List[Path], max_depth: int = 5, limit: int = 100) -> List[Path]:
    """Find .git directories under the given roots.

    Uses `find` for speed. Falls back to Python walk if find unavailable.
    Returns parent directories (the repo roots).
    """
    repos: List[Path] = []
    seen: Set[str] = set()
    for root in roots:
        if not root.exists() or not root.is_dir():
            continue
        try:
            result = subprocess.run(
                ["find", str(root), "-maxdepth", str(max_depth),
                 "-name", ".git", "-type", "d", "-not", "-path", "*/node_modules/*"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            for line in result.stdout.splitlines():
                git_dir = Path(line.strip())
                repo_root = git_dir.parent
                key = str(repo_root.resolve())
                if key in seen:
                    continue
                seen.add(key)
                repos.append(repo_root)
                if len(repos) >= limit:
                    return repos
        except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
            continue
    return repos


def _get_remote_url(repo: Path) -> str:
    """Get origin remote URL, or empty string if none."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _is_writable(path: Path) -> bool:
    """Check if agent process can write to path."""
    return os.access(path, os.W_OK)


def _extract_github_org(remote_url: str) -> str:
    """Extract org/user from github remote URL, or empty if not github."""
    if "github.com" not in remote_url:
        return ""
    # git@github.com:org/repo.git or https://github.com/org/repo.git
    import re
    m = re.search(r"github\.com[:/]([\w.-]+)/[\w.-]+(?:\.git)?$", remote_url)
    return m.group(1) if m else ""


class AdjacentRepoReach(Rule):
    id = "AD-03.adjacent-repo-reach"
    title = "Adjacent repositories reachable with shared credentials"
    severity = Severity.HIGH
    references = [
        "ASAMM AD-02 / AD-03 (Delegation model, blast radius)",
        "ASAMM audit sample: claude-code-zhet (20+ repos writable)",
    ]

    def check_config(self, agent_home: Path, mode=None) -> Iterable[Finding]:
        from ..rules import DetectionMode
        # Only run in FULL mode — this extends trust boundary outside agent_home
        if mode != DetectionMode.AGGRESSIVE and str(mode) != "full":
            return

        # Marker to run only once per audit session
        marker = "_AGENT_AUDIT_ADJACENT_PROBE_RAN"
        if os.environ.get(marker):
            return
        os.environ[marker] = "1"

        # Determine scan roots — env var override or defaults
        env_roots = os.environ.get("AGENT_AUDIT_SCAN_ROOTS")
        if env_roots:
            roots = [Path(r).expanduser() for r in env_roots.split(":") if r.strip()]
        else:
            roots = [Path(r).expanduser() for r in DEFAULT_SCAN_ROOTS]

        repos = _find_git_repos(roots)
        if not repos:
            return

        writable_repos: List[Tuple[Path, str]] = []
        orgs: Set[str] = set()
        for repo in repos:
            if not _is_writable(repo):
                continue
            remote = _get_remote_url(repo)
            if remote:
                writable_repos.append((repo, remote))
                org = _extract_github_org(remote)
                if org:
                    orgs.add(org)

        if len(writable_repos) < 3:
            # Very low blast radius — not worth flagging
            return

        # Higher severity if many repos or cross-org reach
        sev = Severity.HIGH
        if len(writable_repos) >= 10:
            sev = Severity.CRITICAL
        if len(orgs) >= 2:
            sev = Severity.CRITICAL

        # Sample some repos for evidence (avoid huge output)
        samples = writable_repos[:5]
        sample_lines = [
            f"  {repo.name} → {remote}" for repo, remote in samples
        ]
        more = f"\n  ... and {len(writable_repos) - 5} more" if len(writable_repos) > 5 else ""

        yield Finding(
            rule_id=self.id,
            title=self.title,
            severity=sev,
            confidence=Confidence.HIGH,
            summary=(
                f"Found {len(writable_repos)} writable git repositories in your "
                f"home directory with push remotes, spanning {len(orgs)} "
                f"distinct GitHub org(s). An agent running in any one of these "
                f"repos can push to all of them using the same SSH keys. "
                f"Lateral-movement blast radius is not bounded by cwd."
            ),
            evidence=[
                Evidence(
                    description=f"Adjacent writable repos with push remotes",
                    snippet=f"roots={[str(r) for r in roots]}\n" + "\n".join(sample_lines) + more,
                ),
            ],
            remediation=(
                "Options to reduce blast radius:\n"
                "  1. Move sensitive repos outside the agent's accessible root.\n"
                "  2. Use separate SSH keys per org, loaded only when needed.\n"
                "  3. Configure ssh-agent with confirmation: `ssh-add -c ~/.ssh/key`.\n"
                "  4. For critical repos (production security tools), use fine-grained\n"
                "     GitHub tokens scoped to single repos, not full-account PATs.\n"
                "  5. Add `Bash(cd:*/other-org/*)` deny rules in settings.json."
            ),
            references=self.references,
        )


register_config_rule(AdjacentRepoReach())
