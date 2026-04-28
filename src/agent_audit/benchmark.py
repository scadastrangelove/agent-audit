"""Curated benchmark corpus runner for published agent incidents.

Each case lives in a directory with:
  - case.json
  - session.jsonl
  - optional project/ subtree copied to a temporary cwd
  - optional agent_home/ subtree copied under ~/.claude or ~/.codex

The benchmark materializes every case into an isolated fake home, runs the
normal scanner, then scores exact (rule_id, severity) matches.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from .discovery import AgentInstallation
from .events import AgentKind
from .rules import Finding
from .scanner import scan


@dataclass(frozen=True, order=True)
class FindingLabel:
    rule_id: str
    severity: str


@dataclass
class BenchmarkCase:
    id: str
    title: str
    agent: str
    expected_findings: List[FindingLabel]
    description: str = ""
    source_type: str = "published_incident"
    source_url: str | None = None
    source_notes: str | None = None
    tags: List[str] = field(default_factory=list)
    path: Path = field(default_factory=Path)


@dataclass
class BenchmarkCaseResult:
    case_id: str
    title: str
    expected: List[FindingLabel]
    actual: List[FindingLabel]
    true_positives: List[FindingLabel]
    false_negatives: List[FindingLabel]
    false_positives: List[FindingLabel]
    findings: List[dict]

    @property
    def passed(self) -> bool:
        return not self.false_negatives and not self.false_positives


@dataclass
class BenchmarkSummary:
    corpus_path: Path
    generated_at: str
    case_count: int
    passed_cases: int
    failed_cases: int
    expected_total: int
    predicted_total: int
    true_positives: int
    false_negatives: int
    false_positives: int
    precision: float
    recall: float
    per_rule: Dict[str, dict]
    case_results: List[BenchmarkCaseResult]

    def to_dict(self) -> dict:
        return {
            "corpus_path": str(self.corpus_path),
            "generated_at": self.generated_at,
            "case_count": self.case_count,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "expected_total": self.expected_total,
            "predicted_total": self.predicted_total,
            "true_positives": self.true_positives,
            "false_negatives": self.false_negatives,
            "false_positives": self.false_positives,
            "precision": self.precision,
            "recall": self.recall,
            "per_rule": self.per_rule,
            "case_results": [
                {
                    "case_id": cr.case_id,
                    "title": cr.title,
                    "passed": cr.passed,
                    "expected": [asdict(x) for x in cr.expected],
                    "actual": [asdict(x) for x in cr.actual],
                    "true_positives": [asdict(x) for x in cr.true_positives],
                    "false_negatives": [asdict(x) for x in cr.false_negatives],
                    "false_positives": [asdict(x) for x in cr.false_positives],
                    "findings": cr.findings,
                }
                for cr in self.case_results
            ],
        }


def load_corpus(corpus_path: Path) -> List[BenchmarkCase]:
    """Load all benchmark cases under corpus_path."""
    cases: List[BenchmarkCase] = []
    for case_file in sorted(corpus_path.glob("*/case.json")):
        raw = json.loads(case_file.read_text(encoding="utf-8"))
        expected = [
            FindingLabel(
                rule_id=item["rule_id"],
                severity=item["severity"],
            )
            for item in raw.get("expected_findings", [])
        ]
        cases.append(
            BenchmarkCase(
                id=raw["id"],
                title=raw["title"],
                agent=raw["agent"],
                expected_findings=expected,
                description=raw.get("description", ""),
                source_type=raw.get("source_type", "published_incident"),
                source_url=raw.get("source_url"),
                source_notes=raw.get("source_notes"),
                tags=list(raw.get("tags", [])),
                path=case_file.parent,
            )
        )
    return cases


def _agent_home_dir(agent: str, case_home: Path) -> Tuple[AgentKind, str, Path, str]:
    if agent == "claude_code":
        agent_home = case_home / ".claude"
        return (
            AgentKind.CLAUDE_CODE,
            "Claude Code",
            agent_home,
            "projects/**/*.jsonl",
        )
    if agent == "codex":
        agent_home = case_home / ".codex"
        return (
            AgentKind.CODEX,
            "Codex CLI",
            agent_home,
            "sessions/**/*.jsonl",
        )
    raise ValueError(f"Unsupported benchmark agent: {agent}")


def _copy_tree_if_present(src: Path, dst: Path) -> None:
    if not src.exists():
        return
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _replace_tokens(raw: str, *, case_home: Path, agent_home: Path, case_project: Path) -> str:
    rendered = raw
    replacements = {
        "__CASE_HOME__": str(case_home),
        "__AGENT_HOME__": str(agent_home),
        "__CASE_PROJECT__": str(case_project),
        "__CASE_PROJECT_ROOT__": str(case_project),
    }
    for needle, replacement in replacements.items():
        rendered = rendered.replace(needle, replacement)
    return rendered


def _materialize_case(case: BenchmarkCase, workspace_root: Path) -> AgentInstallation:
    case_root = workspace_root / case.id
    case_home = case_root / "home"
    case_project = case_root / "project"
    case_home.mkdir(parents=True, exist_ok=True)
    case_project.mkdir(parents=True, exist_ok=True)

    kind, name, agent_home, sessions_glob = _agent_home_dir(case.agent, case_home)
    agent_home.mkdir(parents=True, exist_ok=True)

    _copy_tree_if_present(case.path / "project", case_project)
    _copy_tree_if_present(case.path / "agent_home", agent_home)

    session_template = (case.path / "session.jsonl").read_text(encoding="utf-8")
    session_body = _replace_tokens(
        session_template,
        case_home=case_home,
        agent_home=agent_home,
        case_project=case_project,
    )

    if case.agent == "claude_code":
        session_path = agent_home / "projects" / "benchmark" / f"{case.id}.jsonl"
    else:
        session_path = agent_home / "sessions" / "2026" / "04" / "21" / f"rollout-{case.id}.jsonl"
    session_path.parent.mkdir(parents=True, exist_ok=True)
    session_path.write_text(session_body, encoding="utf-8")

    return AgentInstallation(
        kind=kind,
        name=name,
        home=agent_home,
        sessions_glob=sessions_glob,
        config_paths=[],
        instruction_paths=[],
        session_count=1,
        total_bytes=session_path.stat().st_size,
    )


def _finding_to_dict(finding: Finding) -> dict:
    return {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "title": finding.title,
        "summary": finding.summary,
    }


def _dedupe_labels(findings: Iterable[Finding]) -> List[FindingLabel]:
    labels = {FindingLabel(rule_id=f.rule_id, severity=f.severity.value) for f in findings}
    return sorted(labels)


def _score_case(case: BenchmarkCase, findings: Sequence[Finding]) -> BenchmarkCaseResult:
    findings = [f for f in findings if not f.rule_id.startswith("probe.")]
    expected = sorted(case.expected_findings)
    actual = _dedupe_labels(findings)
    expected_set = set(expected)
    actual_set = set(actual)
    tp = sorted(expected_set & actual_set)
    fn = sorted(expected_set - actual_set)
    fp = sorted(actual_set - expected_set)
    return BenchmarkCaseResult(
        case_id=case.id,
        title=case.title,
        expected=expected,
        actual=actual,
        true_positives=tp,
        false_negatives=fn,
        false_positives=fp,
        findings=[_finding_to_dict(f) for f in findings],
    )


def run_benchmark(corpus_path: Path) -> BenchmarkSummary:
    """Run all curated cases in corpus_path and score exact labels."""
    corpus_path = corpus_path.resolve()
    cases = load_corpus(corpus_path)
    if not cases:
        raise ValueError(f"No benchmark cases found in {corpus_path}")

    case_results: List[BenchmarkCaseResult] = []
    generated_at = datetime.now().isoformat(timespec="seconds")

    with tempfile.TemporaryDirectory(prefix="agent-audit-benchmark-") as tmp:
        workspace_root = Path(tmp)
        for case in cases:
            installation = _materialize_case(case, workspace_root)
            result = scan(installations=[installation])
            case_results.append(_score_case(case, result.findings))

    expected_total = sum(len(cr.expected) for cr in case_results)
    predicted_total = sum(len(cr.actual) for cr in case_results)
    tp_total = sum(len(cr.true_positives) for cr in case_results)
    fn_total = sum(len(cr.false_negatives) for cr in case_results)
    fp_total = sum(len(cr.false_positives) for cr in case_results)
    passed_cases = sum(1 for cr in case_results if cr.passed)
    failed_cases = len(case_results) - passed_cases

    by_rule: Dict[str, dict] = {}
    for cr in case_results:
        for label in cr.expected:
            bucket = by_rule.setdefault(label.rule_id, {"tp": 0, "fn": 0, "fp": 0, "expected": 0, "predicted": 0})
            bucket["expected"] += 1
        for label in cr.actual:
            bucket = by_rule.setdefault(label.rule_id, {"tp": 0, "fn": 0, "fp": 0, "expected": 0, "predicted": 0})
            bucket["predicted"] += 1
        for label in cr.true_positives:
            by_rule[label.rule_id]["tp"] += 1
        for label in cr.false_negatives:
            by_rule[label.rule_id]["fn"] += 1
        for label in cr.false_positives:
            by_rule[label.rule_id]["fp"] += 1

    for stats in by_rule.values():
        predicted = stats["predicted"]
        expected = stats["expected"]
        stats["precision"] = round(stats["tp"] / predicted, 4) if predicted else 0.0
        stats["recall"] = round(stats["tp"] / expected, 4) if expected else 0.0

    precision = round(tp_total / predicted_total, 4) if predicted_total else 0.0
    recall = round(tp_total / expected_total, 4) if expected_total else 0.0

    return BenchmarkSummary(
        corpus_path=corpus_path,
        generated_at=generated_at,
        case_count=len(case_results),
        passed_cases=passed_cases,
        failed_cases=failed_cases,
        expected_total=expected_total,
        predicted_total=predicted_total,
        true_positives=tp_total,
        false_negatives=fn_total,
        false_positives=fp_total,
        precision=precision,
        recall=recall,
        per_rule=dict(sorted(by_rule.items())),
        case_results=case_results,
    )


def render_markdown(summary: BenchmarkSummary) -> str:
    """Render benchmark summary as markdown."""
    lines = [
        "# Agent-audit benchmark",
        f"_generated {summary.generated_at}_",
        "",
        "## Score",
        "",
        f"- Corpus: `{summary.corpus_path}`",
        f"- Cases: {summary.case_count}",
        f"- Passed: {summary.passed_cases}",
        f"- Failed: {summary.failed_cases}",
        f"- Expected labels: {summary.expected_total}",
        f"- Predicted labels: {summary.predicted_total}",
        f"- True positives: {summary.true_positives}",
        f"- False negatives: {summary.false_negatives}",
        f"- False positives: {summary.false_positives}",
        f"- Precision: {summary.precision:.4f}",
        f"- Recall: {summary.recall:.4f}",
        "",
        "## Per Rule",
        "",
    ]

    for rule_id, stats in summary.per_rule.items():
        lines.append(
            f"- `{rule_id}`: precision={stats['precision']:.4f}, "
            f"recall={stats['recall']:.4f}, tp={stats['tp']}, "
            f"fn={stats['fn']}, fp={stats['fp']}"
        )

    lines.extend(["", "## Cases", ""])
    for case in summary.case_results:
        status = "PASS" if case.passed else "FAIL"
        lines.append(f"- **{status}** `{case.case_id}` — {case.title}")
        if case.false_negatives:
            lines.append(
                f"  missing: {', '.join(f'{x.rule_id}:{x.severity}' for x in case.false_negatives)}"
            )
        if case.false_positives:
            lines.append(
                f"  extra: {', '.join(f'{x.rule_id}:{x.severity}' for x in case.false_positives)}"
            )
    lines.append("")
    return "\n".join(lines)


def write_reports(summary: BenchmarkSummary, output_dir: Path) -> Tuple[Path, Path]:
    """Write JSON + Markdown benchmark reports."""
    output_dir.mkdir(parents=True, exist_ok=True)
    json_path = output_dir / "benchmark-summary.json"
    md_path = output_dir / "benchmark-summary.md"
    json_path.write_text(json.dumps(summary.to_dict(), indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(summary), encoding="utf-8")
    return json_path, md_path
