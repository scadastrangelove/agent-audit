"""credential.context-bleed — agent used credentials outside project scope.

Motivated by the April 2026 Reddit r/ClaudeAI report: agent generated
`export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/old-project-creds.json`
and deleted 25,000 documents from the wrong Google Cloud project.

Pattern: agent sets or uses credential paths / cloud profiles from
directories outside the current working directory — typically Downloads,
Desktop, /tmp, or another project folder. This is distinct from
credential-exfil (C2): here the agent isn't leaking credentials outward,
it's using the WRONG credentials to act on systems the user didn't
intend to touch.

Detection classes:
  1. Credential env var export pointing to a path outside cwd
     (GOOGLE_APPLICATION_CREDENTIALS, AWS_SHARED_CREDENTIALS_FILE,
     KUBECONFIG, etc.)
  2. CLI profile switches (`--profile other-profile`, `aws sso login`
     with a different account ID)
  3. Kubectl context switches to a non-current cluster

Severity: HIGH — can cause destructive action on unrelated systems.
Bumped to CRITICAL if the same window contains destructive ops.
"""
from __future__ import annotations

import re
from typing import Iterable, List, Optional, Tuple

from ..events import Event, EventType, Session
from ..nlu import taint
from ..rules import (
    Confidence,
    Evidence,
    Finding,
    Rule,
    Severity,
    register_session_rule,
)


# Credential environment variables that determine which cloud account
# / project / cluster operations apply to.
_CRED_ENV_VARS = (
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_CONFIG_FILE",
    "AWS_PROFILE",
    "AWS_ACCESS_KEY_ID",         # fresh keys from elsewhere
    "AWS_SESSION_TOKEN",
    "KUBECONFIG",
    "GCLOUD_CONFIG_DIR",
    "AZURE_CONFIG_DIR",
    "CLOUDSDK_CORE_PROJECT",     # switching GCP project
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "GITHUB_TOKEN",              # separate token from elsewhere
    "VAULT_TOKEN",
)


# Directories that typically contain credentials from OTHER projects —
# red flag when agent pulls from here.
_OFF_PROJECT_DIRS = re.compile(
    r"""
    (?:
        ~/Downloads/
      | /Users/[^/]+/Downloads/
      | /home/[^/]+/Downloads/
      | ~/Desktop/
      | /Users/[^/]+/Desktop/
      | /home/[^/]+/Desktop/
      | /tmp/
      | /var/tmp/
      | ~/Documents/(?!.*current|.*active)  # Documents/old-project/...
    )
    """,
    re.VERBOSE,
)


# Pattern: export/set of a credential env var assigning a path or value.
_EXPORT_CRED = re.compile(
    r"""
    (?:^|[\s;&|])
    (?:export\s+|set\s+|setenv\s+)?
    (?P<var>GOOGLE_APPLICATION_CREDENTIALS | AWS_SHARED_CREDENTIALS_FILE
          | AWS_CONFIG_FILE | AWS_PROFILE | AWS_ACCESS_KEY_ID
          | AWS_SESSION_TOKEN | KUBECONFIG | GCLOUD_CONFIG_DIR
          | AZURE_CONFIG_DIR | CLOUDSDK_CORE_PROJECT
          | CLOUDSDK_ACTIVE_CONFIG_NAME | GITHUB_TOKEN | VAULT_TOKEN)
    \s*=\s*
    (?P<value>[^\s;&|]+)
    """,
    re.VERBOSE | re.IGNORECASE,
)


# Profile / context switches that redirect CLI to a different scope.
_PROFILE_SWITCH = re.compile(
    r"""
    (?:
        # AWS profile switch with explicit name
        \baws\s+[^|&;]*--profile\s+(?P<aws_prof>\S+)
      | \baws\s+configure\s+set\s+[^|&;]*--profile\s+(?P<aws_cfg_prof>\S+)
        # gcloud — switching active config or project
      | \bgcloud\s+config\s+set\s+project\s+(?P<gcp_proj>\S+)
      | \bgcloud\s+config\s+configurations\s+activate\s+(?P<gcp_cfg>\S+)
        # kubectl context switch
      | \bkubectl\s+config\s+use-context\s+(?P<k8s_ctx>\S+)
      | \bkubectx\s+(?P<kctx>\S+)
        # az account set
      | \baz\s+account\s+set\s+[^|&;]*--subscription\s+(?P<az_sub>\S+)
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)


def _bash_cmd(event: Event) -> str:
    if event.type != EventType.TOOL_USE:
        return ""
    if (event.tool_name or "").lower() not in ("bash", "shell") and getattr(event, "canonical_tool", None) != "Bash":
        return ""
    for key in ("command", "cmd", "script"):
        v = (event.tool_input or {}).get(key)
        if isinstance(v, str):
            return v
    return ""


def _path_is_off_project(path: str, session_cwd: Optional[str]) -> bool:
    """True if `path` sits outside the session's cwd and matches an
    off-project directory (Downloads/Desktop/tmp/other-project)."""
    if not path:
        return False
    # Strip quoting
    path = path.strip().strip("'\"")
    if _OFF_PROJECT_DIRS.search(path):
        return True
    # If session cwd is known, any absolute path outside it is suspicious
    if session_cwd and path.startswith("/") and not path.startswith(session_cwd):
        # But only flag if it's credentials-looking (has .json, creds, etc.)
        if re.search(r"(credential|\.json|token|key|secret)", path, re.IGNORECASE):
            return True
    return False


def _has_destructive_op_in_window(session: Session, start_turn: int,
                                   end_turn: int) -> bool:
    """True if any destructive sink fires between start_turn (exclusive)
    and end_turn (inclusive). Uses taint classification for consistency."""
    for ev in session.events:
        if ev.turn_index <= start_turn or ev.turn_index > end_turn + 20:
            continue
        cls = taint.classify_event(ev)
        if taint.TaintSink.DESTRUCTIVE in cls.sinks:
            return True
        # Also flag cloud delete operations which taint doesn't always catch
        if (ev.tool_name or "").lower() in ("bash", "shell") or getattr(ev, "canonical_tool", None) == "Bash":
            cmd = _bash_cmd(ev)
            if re.search(
                r"""\b(?:
                    gcloud(?:\s+\S+){0,4}\s+delete
                  | aws(?:\s+\S+){0,4}\s+delete
                  | aws\s+s3\s+rm
                  | az(?:\s+\S+){0,4}\s+delete
                  | kubectl\s+delete
                )\b""",
                cmd,
                re.IGNORECASE | re.VERBOSE,
            ):
                return True
        # USER_MESSAGE closes the window
        if ev.type == EventType.USER_MESSAGE:
            break
    return False


class CredentialContextBleed(Rule):
    """Agent set credentials from outside the project, potentially acting
    on an unrelated account/project/cluster.
    """

    id = "credential.context-bleed"
    title = "Credential context switch to out-of-project scope"
    severity = Severity.HIGH
    references = [
        "Reddit r/ClaudeAI (Apr 2026) — Claude Code picked up "
        "GOOGLE_APPLICATION_CREDENTIALS from ~/Downloads, deleted 25k "
        "documents from wrong GCP project",
        "ASAMM AD-02 (Delegation boundary) + C2 (Context integrity)",
    ]

    def check_session(self, session: Session) -> Iterable[Finding]:
        cwd = session.cwd  # Session-level cwd

        for event in session.events:
            cmd = _bash_cmd(event)
            if not cmd:
                continue

            findings_this_event: List[Tuple[str, str, str]] = []

            # Env var export
            for m in _EXPORT_CRED.finditer(cmd):
                var = m.group("var").upper()
                value = m.group("value").strip('"\'')
                # Value can be a path (creds file) or opaque token string
                if "/" in value or value.startswith("~") or value.startswith("$"):
                    if _path_is_off_project(value, cwd):
                        findings_this_event.append((
                            "cred_env_off_project",
                            f"{var}={value}",
                            f"credential environment variable {var} pointed "
                            f"to a path outside the project scope: {value}",
                        ))
                else:
                    # Non-path value (profile name or token). Less certain,
                    # but still worth surfacing for profiles.
                    if var in ("AWS_PROFILE", "CLOUDSDK_ACTIVE_CONFIG_NAME",
                               "CLOUDSDK_CORE_PROJECT"):
                        findings_this_event.append((
                            "cred_profile_switch_env",
                            f"{var}={value}",
                            f"credential scope switched via env: {var}={value}",
                        ))

            # CLI profile/context switch
            for m in _PROFILE_SWITCH.finditer(cmd):
                names = [n for n in m.groupdict().values() if n]
                if names:
                    findings_this_event.append((
                        "cli_profile_switch",
                        m.group(0),
                        f"CLI profile or context switch: {m.group(0).strip()}",
                    ))

            if not findings_this_event:
                continue

            for category, evidence_str, summary_piece in findings_this_event:
                # Severity escalation if destructive op follows in same window
                destructive_follows = _has_destructive_op_in_window(
                    session, event.turn_index, event.turn_index
                )
                sev = Severity.CRITICAL if destructive_follows else Severity.HIGH
                if session.is_subagent:
                    if sev == Severity.CRITICAL:
                        sev = Severity.HIGH
                    elif sev == Severity.HIGH:
                        sev = Severity.MEDIUM

                yield Finding(
                    rule_id=self.id,
                    title=self.title,
                    severity=sev,
                    confidence=Confidence.HIGH,
                    summary=(
                        f"Agent {summary_piece}. "
                        f"{'A destructive operation followed in the same window — '
                          'this is the pattern that caused the April 2026 Claude '
                          'Code incident where 25k documents were deleted from '
                          'the wrong GCP project. ' if destructive_follows else ''}"
                        f"Check whether the agent's credential scope matched "
                        f"the user's intent."
                    ),
                    evidence=[
                        Evidence(
                            description=f"Credential context change ({category})",
                            source=session.source_file,
                            session_id=session.session_id,
                            turn_range=(event.turn_index, event.turn_index),
                            snippet=evidence_str[:200],
                        ),
                    ],
                    remediation=(
                        "Verify the credential/profile scope matches the user's "
                        "intended target. Mitigations:\n"
                        "  • Set AGENT_AUDIT_DISALLOW_DOWNLOADS_CREDS in shell "
                        "environment to catch this via wrapper\n"
                        "  • Use per-project credential files via direnv/dotenv "
                        "— never ~/Downloads or ~/Desktop\n"
                        "  • For Claude Code: add Bash(*:--profile:*) and "
                        "Bash(*:KUBECONFIG=*) to the approval-required list in "
                        "settings.json\n"
                        "  • Review recent activity in the target account/project "
                        "for any unintended modifications"
                    ),
                    references=self.references,
                    needs_llm_verification=True,
                )


register_session_rule(CredentialContextBleed())
