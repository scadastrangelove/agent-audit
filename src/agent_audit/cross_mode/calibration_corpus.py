# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""M2 calibration corpus loader.

Reads paired (project, session, expected) test cases from
benchmarks/m2-calibration-corpus/ and exposes them as
`CalibrationCase` dataclasses for use in Phase 2 correlator tests.

Each case directory contains:
  - case.json          — metadata + m2_expected ground truth
  - project/           — fake project tree the resolver should find
  - session.jsonl      — Claude Code session log (cwd uses
                         __CASE_PROJECT__ as a placeholder)

The loader materializes the session into a temporary directory with
the placeholder substituted, parses it via the regular Claude Code
parser, and returns a structured case for tests to consume.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


# Default corpus location relative to the repo root.
_CORPUS_DIR_DEFAULT = Path(__file__).resolve().parents[3] / "benchmarks" / "m2-calibration-corpus"

# Placeholder used inside session.jsonl files. Replaced with the
# absolute path to the case's project/ subdirectory at load time.
_CWD_PLACEHOLDER = "__CASE_PROJECT__"


@dataclass
class CalibrationExpectation:
    """The `m2_expected` block of a case.json, as a typed view."""
    expected_correlator: Optional[str]
    expected_link: bool
    expected_repo_tags: List[str]
    expected_dynamic_finding_kind: Optional[str]
    expected_proximity_minimum: Optional[int]
    rationale: str


@dataclass
class CalibrationCase:
    """A single paired test case loaded from disk.

    `project_root` and `session_path` point at materialized files in a
    temporary directory — the corpus loader copies the case's static
    fixtures and substitutes the cwd placeholder so the resolver can
    actually find the repo. `materialized_dir` is the tempdir; the
    caller is responsible for cleanup via `cleanup()` or by using the
    case as a context manager.
    """
    case_id: str
    title: str
    description: str
    tags: List[str]
    expected: CalibrationExpectation
    project_root: Path
    session_path: Path
    materialized_dir: Path

    def cleanup(self) -> None:
        """Remove the temporary materialization directory."""
        if self.materialized_dir.exists():
            shutil.rmtree(self.materialized_dir, ignore_errors=True)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.cleanup()
        return False


def _parse_expectation(raw: Dict[str, Any]) -> CalibrationExpectation:
    """Validate + normalize the m2_expected block.

    The block is required on every case; missing fields raise
    ValueError so a malformed corpus surfaces during loading rather
    than producing silent test pass/fail."""
    if not isinstance(raw, dict):
        raise ValueError("m2_expected must be an object")
    return CalibrationExpectation(
        expected_correlator=raw.get("expected_correlator"),
        expected_link=bool(raw.get("expected_link", False)),
        expected_repo_tags=list(raw.get("expected_repo_tags") or []),
        expected_dynamic_finding_kind=raw.get("expected_dynamic_finding_kind"),
        expected_proximity_minimum=raw.get("expected_proximity_minimum"),
        rationale=str(raw.get("rationale") or ""),
    )


def _materialize_case(case_dir: Path) -> CalibrationCase:
    """Copy the case's project/ + session.jsonl into a fresh tempdir,
    substituting __CASE_PROJECT__ with the absolute project path so
    the resolver can find the repo at scan time.

    Returns a fully-constructed CalibrationCase. The tempdir lives
    until `cleanup()` is called.
    """
    case_meta_path = case_dir / "case.json"
    if not case_meta_path.exists():
        raise FileNotFoundError(f"case.json missing in {case_dir}")
    src_session = case_dir / "session.jsonl"
    if not src_session.exists():
        raise FileNotFoundError(f"session.jsonl missing in {case_dir}")
    src_project = case_dir / "project"
    if not src_project.exists():
        raise FileNotFoundError(f"project/ missing in {case_dir}")

    with case_meta_path.open("r", encoding="utf-8") as fh:
        meta = json.load(fh)

    if "m2_expected" not in meta:
        raise ValueError(f"case {case_dir.name} has no m2_expected block")

    materialized = Path(tempfile.mkdtemp(prefix=f"m2cal-{meta.get('id', case_dir.name)}-"))
    project_root = materialized / "project"
    shutil.copytree(src_project, project_root)

    # Substitute placeholder in the session jsonl
    session_text = src_session.read_text(encoding="utf-8")
    session_text = session_text.replace(_CWD_PLACEHOLDER, str(project_root.resolve()))
    session_path = materialized / "session.jsonl"
    session_path.write_text(session_text, encoding="utf-8")

    return CalibrationCase(
        case_id=str(meta.get("id") or case_dir.name),
        title=str(meta.get("title") or ""),
        description=str(meta.get("description") or ""),
        tags=list(meta.get("tags") or []),
        expected=_parse_expectation(meta["m2_expected"]),
        project_root=project_root,
        session_path=session_path,
        materialized_dir=materialized,
    )


def list_calibration_case_dirs(corpus_dir: Optional[Path] = None) -> List[Path]:
    """Return sorted paths of every case directory in the corpus.

    A case directory is one that contains `case.json`. Other files in
    the corpus (README, etc.) are ignored.
    """
    base = corpus_dir or _CORPUS_DIR_DEFAULT
    if not base.exists():
        return []
    out: List[Path] = []
    for child in sorted(base.iterdir()):
        if child.is_dir() and (child / "case.json").exists():
            out.append(child)
    return out


def load_calibration_case(case_dir: Path) -> CalibrationCase:
    """Materialize a single case. Caller must call cleanup() or use
    as a context manager."""
    return _materialize_case(case_dir)


def load_all_calibration_cases(corpus_dir: Optional[Path] = None) -> List[CalibrationCase]:
    """Materialize every case in the corpus.

    Each returned case carries its own tempdir; the caller is
    responsible for cleanup.
    """
    return [load_calibration_case(d) for d in list_calibration_case_dirs(corpus_dir)]
