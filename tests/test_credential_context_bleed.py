"""Unit tests for credential.context-bleed.

Covers off-project credential env var exports, CLI profile switches,
and destructive-op escalation.
"""
from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from agent_audit.events import Event, EventType, AgentKind, Session
from agent_audit.detectors.credential_context_bleed import (
    CredentialContextBleed, _path_is_off_project, _EXPORT_CRED, _PROFILE_SWITCH,
)
from agent_audit.rules import Severity


def mk_bash(turn, cmd):
    return Event(
        session_id="t", turn_index=turn,
        timestamp=datetime(2026, 4, 19, 10, 0, turn),
        agent=AgentKind.CLAUDE_CODE, type=EventType.TOOL_USE,
        role="assistant", tool_name="Bash",
        tool_input={"command": cmd},
    )


def mk_session(events, cwd=None):
    s = Session(
        session_id="t", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 1, 0),
        events=events,
    )
    if cwd:
        s.cwd = cwd
    return s


# =============================================================================
# Path classification
# =============================================================================


def test_downloads_is_off_project():
    assert _path_is_off_project("~/Downloads/creds.json", "/home/user/project")
    assert _path_is_off_project("/Users/alice/Downloads/key.json", "/project")
    assert _path_is_off_project("/home/bob/Downloads/creds.json", None)


def test_desktop_is_off_project():
    assert _path_is_off_project("~/Desktop/key.json", "/project")


def test_tmp_is_off_project():
    assert _path_is_off_project("/tmp/creds.json", "/project")
    assert _path_is_off_project("/var/tmp/key.json", "/project")


def test_project_local_path_not_off_project():
    """Path inside cwd is not off-project."""
    assert not _path_is_off_project(
        "/home/user/project/.env", "/home/user/project"
    )
    # Relative path — not off-project
    assert not _path_is_off_project("config/creds.json", "/project")


def test_regex_captures_google_creds():
    cmd = "export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/creds.json"
    m = _EXPORT_CRED.search(cmd)
    assert m
    assert m.group("var") == "GOOGLE_APPLICATION_CREDENTIALS"
    assert "Downloads" in m.group("value")


def test_regex_captures_aws_profile():
    cmd = "aws s3 ls --profile other-account"
    m = _PROFILE_SWITCH.search(cmd)
    assert m
    assert m.group("aws_prof") == "other-account"


def test_regex_captures_kubectl_context():
    cmd = "kubectl config use-context prod-cluster"
    m = _PROFILE_SWITCH.search(cmd)
    assert m
    assert m.group("k8s_ctx") == "prod-cluster"


def test_regex_captures_gcloud_project():
    cmd = "gcloud config set project other-production-project"
    m = _PROFILE_SWITCH.search(cmd)
    assert m
    assert m.group("gcp_proj") == "other-production-project"


# =============================================================================
# Detector behavior — the attachment case
# =============================================================================


def test_google_creds_from_downloads_triggers():
    """The canonical attachment case — Reddit r/ClaudeAI Apr 2026."""
    session = mk_session([
        mk_bash(0, "export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/old-creds.json"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1
    assert findings[0].rule_id == "credential.context-bleed"


def test_destructive_follow_escalates_to_critical():
    """If destructive op follows the credential change → CRITICAL."""
    session = mk_session([
        mk_bash(0, "export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/creds.json"),
        mk_bash(1, "gcloud firestore documents delete --all-collections"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_no_destructive_follow_is_high():
    """Cred switch alone, no destructive op → HIGH (lower)."""
    session = mk_session([
        mk_bash(0, "export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/creds.json"),
        mk_bash(1, "gcloud projects list"),  # read-only
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_aws_profile_switch_triggers():
    session = mk_session([
        mk_bash(0, "aws s3 ls --profile prod-other"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1


def test_kubectl_context_switch_triggers():
    session = mk_session([
        mk_bash(0, "kubectl config use-context production-cluster-east"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1


def test_project_local_cred_does_not_fire():
    """Credentials inside project — not a bleed."""
    session = mk_session([
        mk_bash(0, "export GOOGLE_APPLICATION_CREDENTIALS=./secrets/app-creds.json"),
    ], cwd="/home/user/project")
    findings = list(CredentialContextBleed().check_session(session))
    # Relative path in cwd should not fire
    assert findings == []


def test_non_credential_export_ignored():
    """Regular env vars shouldn't trigger."""
    session = mk_session([
        mk_bash(0, "export NODE_ENV=production"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert findings == []


def test_azure_subscription_switch():
    session = mk_session([
        mk_bash(0, "az account set --subscription my-prod-subscription"),
    ])
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1


# =============================================================================
# Subagent
# =============================================================================


def test_subagent_downgrade():
    events = [
        mk_bash(0, "export GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/creds.json"),
        mk_bash(1, "gcloud firestore documents delete --all-collections"),
    ]
    session = Session(
        session_id="sub", agent=AgentKind.CLAUDE_CODE,
        source_file=Path("/fake"),
        started_at=datetime(2026, 4, 19, 10, 0, 0),
        last_activity=datetime(2026, 4, 19, 10, 1, 0),
        events=events, is_subagent=True,
    )
    findings = list(CredentialContextBleed().check_session(session))
    assert len(findings) == 1
    # CRITICAL → HIGH in subagent
    assert findings[0].severity == Severity.HIGH


if __name__ == "__main__":
    import traceback
    tests = [v for k, v in globals().items() if k.startswith("test_") and callable(v)]
    passed = 0
    failed = []
    for t in tests:
        try:
            t()
            passed += 1
        except Exception as e:
            failed.append((t.__name__, traceback.format_exc()))
    print(f"\n{passed}/{len(tests)} tests passed")
    for name, tb in failed:
        print(f"\n  FAIL: {name}")
        print(f"    {tb.splitlines()[-1]}")
    if failed:
        sys.exit(1)
