# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Real-data evaluation harness for agent-audit (v0.19).

Extends the existing `benchmark` subcommand with:

  - End-to-end run of scan + scan-project + cross-mode on each case
  - Per-stage perf timings (so a regression isolates to a specific phase)
  - Cross-mode aggregate-record scoring against expected_correlators
  - Drift detection vs a baseline (CI mode)

Designed to replace the audit-time question "did anything regress?"
with a single command and a comparable artifact across runs.

Background: the v0.17/v0.18 hypothesis audit identified 5 ПФЗ items
(production claims not verified on real data). Each ПФЗ item became
"verified" only when the corresponding pipeline ran on a real corpus
with measurable outcomes. This harness institutionalizes that
discipline — every release should have an `eval` artifact that lets
the maintainer answer "is this a real-data regression or noise?"
without re-running stages by hand.

The corpus expansion contract: cases live under benchmarks/incident-corpus/
with the existing case.json schema. v0.19 adds optional fields:

  expected_static_findings: list of {rule_id, severity}
      Rules expected to fire when scan-project runs against the
      case's project/ subtree. Optional — many cases don't ship a
      project/, in which case scan-project produces no findings.

  expected_correlators: list of {correlator, severity}
      Cross-mode aggregate records expected when both forensic and
      static sides fire matching signals. Optional — most current
      cases have no expected correlator (sessions don't co-occur with
      instruction surfaces in the materialized layout).

  expected_runtime_budget_seconds: float
      Maximum acceptable scan+cross-mode time. The harness flags cases
      that exceed budget without failing the case (perf is a separate
      track from precision/recall).

A case missing these new fields is treated permissively — the harness
won't expect static findings or correlators for it, but won't penalize
either. Migration is purely additive.
"""
from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .benchmark import (
    BenchmarkCase,
    BenchmarkCaseResult,
    FindingLabel,
    _materialize_case,
    _score_case,
    load_corpus,
)
from .rules import Finding
from .scanner import scan


@dataclass
class StageTimings:
    """Per-stage wall time in seconds."""
    scan_seconds: float = 0.0
    scan_project_seconds: float = 0.0
    cross_mode_seconds: float = 0.0  # cross-mode is part of scan() in v0.18.3+

    @property
    def total_seconds(self) -> float:
        return self.scan_seconds + self.scan_project_seconds


@dataclass
class CorrelatorLabel:
    """Expected cross-mode aggregate."""
    correlator: str
    severity: str = "high"

    def matches(self, agg_record: dict) -> bool:
        return (
            agg_record.get("correlator") == self.correlator
            and agg_record.get("severity") == self.severity
        )


@dataclass
class EvalCaseResult:
    """End-to-end result for one case in the harness."""
    case_id: str
    title: str
    forensic: BenchmarkCaseResult  # standard benchmark result
    static_predicted: List[FindingLabel] = field(default_factory=list)
    static_expected: List[FindingLabel] = field(default_factory=list)
    static_true_positives: List[FindingLabel] = field(default_factory=list)
    static_false_negatives: List[FindingLabel] = field(default_factory=list)
    correlator_predicted: List[CorrelatorLabel] = field(default_factory=list)
    correlator_expected: List[CorrelatorLabel] = field(default_factory=list)
    correlator_true_positives: List[CorrelatorLabel] = field(default_factory=list)
    correlator_false_negatives: List[CorrelatorLabel] = field(default_factory=list)
    timings: StageTimings = field(default_factory=StageTimings)
    runtime_budget_seconds: Optional[float] = None
    over_budget: bool = False

    @property
    def passed(self) -> bool:
        """End-to-end pass: forensic, static, correlator all clean."""
        return (
            self.forensic.passed
            and not self.static_false_negatives
            and not self.correlator_false_negatives
        )


@dataclass
class EvalSummary:
    """Aggregate metrics across the corpus."""
    corpus_path: str
    generated_at: str
    case_count: int
    passed_cases: int
    failed_cases: int
    over_budget_cases: int

    # Forensic side metrics (mirrors benchmark.BenchmarkSummary)
    forensic_tp: int
    forensic_fn: int
    forensic_fp: int
    forensic_precision: float
    forensic_recall: float

    # Static side metrics
    static_tp: int
    static_fn: int
    static_recall: float

    # Cross-mode side metrics
    correlator_tp: int
    correlator_fn: int
    correlator_recall: float

    # Perf metrics
    total_wall_seconds: float
    median_case_seconds: float
    max_case_seconds: float

    case_results: List[EvalCaseResult] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "corpus_path": self.corpus_path,
            "generated_at": self.generated_at,
            "case_count": self.case_count,
            "passed_cases": self.passed_cases,
            "failed_cases": self.failed_cases,
            "over_budget_cases": self.over_budget_cases,
            "forensic": {
                "tp": self.forensic_tp, "fn": self.forensic_fn, "fp": self.forensic_fp,
                "precision": self.forensic_precision, "recall": self.forensic_recall,
            },
            "static": {
                "tp": self.static_tp, "fn": self.static_fn,
                "recall": self.static_recall,
            },
            "correlator": {
                "tp": self.correlator_tp, "fn": self.correlator_fn,
                "recall": self.correlator_recall,
            },
            "perf": {
                "total_wall_seconds": self.total_wall_seconds,
                "median_case_seconds": self.median_case_seconds,
                "max_case_seconds": self.max_case_seconds,
            },
            "case_results": [
                {
                    "case_id": cr.case_id, "title": cr.title,
                    "passed": cr.passed,
                    "forensic": {
                        "expected": [asdict(x) for x in cr.forensic.expected],
                        "actual": [asdict(x) for x in cr.forensic.actual],
                        "tp": [asdict(x) for x in cr.forensic.true_positives],
                        "fn": [asdict(x) for x in cr.forensic.false_negatives],
                        "fp": [asdict(x) for x in cr.forensic.false_positives],
                    },
                    "static": {
                        "expected": [asdict(x) for x in cr.static_expected],
                        "predicted": [asdict(x) for x in cr.static_predicted],
                        "tp": [asdict(x) for x in cr.static_true_positives],
                        "fn": [asdict(x) for x in cr.static_false_negatives],
                    },
                    "correlator": {
                        "expected": [asdict(x) for x in cr.correlator_expected],
                        "predicted": [asdict(x) for x in cr.correlator_predicted],
                        "tp": [asdict(x) for x in cr.correlator_true_positives],
                        "fn": [asdict(x) for x in cr.correlator_false_negatives],
                    },
                    "timings": asdict(cr.timings),
                    "over_budget": cr.over_budget,
                    "runtime_budget_seconds": cr.runtime_budget_seconds,
                }
                for cr in self.case_results
            ],
        }


def _load_v019_extensions(case: BenchmarkCase) -> Tuple[
    List[FindingLabel],  # expected_static_findings
    List[CorrelatorLabel],  # expected_correlators
    Optional[float],  # expected_runtime_budget_seconds
]:
    """Pull v0.19-extension fields from the raw case.json. Missing
    fields are treated as empty/None — purely additive migration."""
    raw = json.loads((case.path / "case.json").read_text(encoding="utf-8"))
    static_expected = [
        FindingLabel(rule_id=item["rule_id"], severity=item.get("severity", "high"))
        for item in raw.get("expected_static_findings") or []
        if _static_rule_runtime_available(item["rule_id"])
    ]
    correlator_expected = [
        CorrelatorLabel(
            correlator=item["correlator"],
            severity=item.get("severity", "high"),
        )
        for item in raw.get("expected_correlators") or []
    ]
    budget = raw.get("expected_runtime_budget_seconds")
    return static_expected, correlator_expected, budget


def _static_rule_runtime_available(rule_id: str) -> bool:
    """Return True when the current runtime can emit the given static rule.

    Some static detectors are guarded by optional extras. The eval harness
    should not mark those as false negatives when the dependency is absent,
    otherwise correctness starts depending on whether the maintainer happened
    to install an optional package locally.
    """
    if rule_id.startswith("A5.cisco-yara-"):
        try:
            from .detectors import mcp_yara_scanner
            return mcp_yara_scanner.is_available()
        except Exception:
            return False
    return True


def _run_scan_project(case_project: Path) -> List[FindingLabel]:
    """Run scan-project on the case's project subtree. Returns empty
    list if no project subtree was materialized.

    Imports project_scanner lazily so this module doesn't pull in
    static-scan dependencies at top level.
    """
    from .project_scanner import scan_project

    if not case_project.exists() or not any(case_project.iterdir()):
        return []
    result = scan_project(case_project)
    return [
        FindingLabel(rule_id=f.rule_id, severity=f.severity.value)
        for f in result.findings
    ]


def _score_static_findings(
    expected: List[FindingLabel],
    actual: List[FindingLabel],
) -> Tuple[List[FindingLabel], List[FindingLabel]]:
    """Return (true_positives, false_negatives). FPs are not penalized
    here — scan-project on a real project legitimately fires lots of
    findings that aren't in the curated expected list. The harness
    cares about recall: did we catch what we said we'd catch?"""
    actual_set = {(f.rule_id, f.severity) for f in actual}
    tp = [e for e in expected if (e.rule_id, e.severity) in actual_set]
    fn = [e for e in expected if (e.rule_id, e.severity) not in actual_set]
    return tp, fn


def _score_correlator_findings(
    expected: List[CorrelatorLabel],
    aggregate_records: List[dict],
) -> Tuple[List[CorrelatorLabel], List[CorrelatorLabel], List[CorrelatorLabel]]:
    """Return (predicted_labels, true_positives, false_negatives) over
    cross-mode aggregate records."""
    predicted = [
        CorrelatorLabel(
            correlator=r.get("correlator", ""),
            severity=r.get("severity", "high"),
        )
        for r in aggregate_records
    ]
    pred_set = {(p.correlator, p.severity) for p in predicted}
    tp = [e for e in expected if (e.correlator, e.severity) in pred_set]
    fn = [e for e in expected if (e.correlator, e.severity) not in pred_set]
    return predicted, tp, fn


def evaluate_corpus(
    corpus_path: Path,
    *,
    on_progress: Optional[callable] = None,
) -> EvalSummary:
    """Run the full eval pipeline over a corpus and return the summary.

    Each case:
      1. Materialize into a workspace dir (outside /tmp/ to avoid
         AG-04 ephemeral filter — see benchmark.run_benchmark).
      2. Run scan() with cross_mode=True → forensic findings + cross_mode_report.
      3. Run scan-project on the materialized project subtree → static findings.
      4. Score against case's expected_findings / expected_static_findings /
         expected_correlators.
      5. Record per-stage timings.
    """
    corpus_path = corpus_path.resolve()
    cases = load_corpus(corpus_path)
    if not cases:
        raise ValueError(f"No benchmark cases found in {corpus_path}")

    home_dir = Path(os.environ.get("HOME", os.path.expanduser("~")))
    bench_parent = home_dir / ".cache" / "agent-audit"
    bench_parent.mkdir(parents=True, exist_ok=True)

    case_results: List[EvalCaseResult] = []
    overall_start = time.perf_counter()

    with tempfile.TemporaryDirectory(
        prefix="agent-audit-eval-", dir=str(bench_parent),
    ) as tmp:
        workspace_root = Path(tmp)
        for i, case in enumerate(cases, 1):
            if on_progress:
                on_progress(f"[{i}/{len(cases)}] {case.id}")

            installation = _materialize_case(case, workspace_root)
            case_project = workspace_root / case.id / "project"
            if case_project.exists():
                # Keep repo resolution anchored inside the materialized case.
                # Without a repo marker here, cross-mode can walk upward and
                # inventory the maintainer's home tree instead of the case.
                (case_project / ".git").mkdir(exist_ok=True)

            # Stage 1: scan (with cross-mode enabled)
            t0 = time.perf_counter()
            scan_result = scan(installations=[installation])
            scan_secs = time.perf_counter() - t0

            forensic_cr = _score_case(case, scan_result.findings)

            # Cross-mode metrics from the integrated report
            cm = scan_result.cross_mode_report or {}
            agg_records = cm.get("aggregate_records") or []
            cm_secs = 0.0  # already counted in scan_secs since v0.18.3 integrates

            # Stage 2: scan-project
            t0 = time.perf_counter()
            static_predicted = _run_scan_project(case_project)
            scan_project_secs = time.perf_counter() - t0

            # Score
            static_expected, correlator_expected, budget = _load_v019_extensions(case)
            static_tp, static_fn = _score_static_findings(static_expected, static_predicted)
            corr_predicted, corr_tp, corr_fn = _score_correlator_findings(
                correlator_expected, agg_records,
            )

            timings = StageTimings(
                scan_seconds=scan_secs,
                scan_project_seconds=scan_project_secs,
                cross_mode_seconds=cm_secs,
            )
            over_budget = bool(budget) and timings.total_seconds > budget

            case_results.append(EvalCaseResult(
                case_id=case.id,
                title=case.title,
                forensic=forensic_cr,
                static_expected=static_expected,
                static_predicted=static_predicted,
                static_true_positives=static_tp,
                static_false_negatives=static_fn,
                correlator_expected=correlator_expected,
                correlator_predicted=corr_predicted,
                correlator_true_positives=corr_tp,
                correlator_false_negatives=corr_fn,
                timings=timings,
                runtime_budget_seconds=budget,
                over_budget=over_budget,
            ))

    overall_seconds = time.perf_counter() - overall_start

    # Aggregate
    fp_tp = sum(len(cr.forensic.true_positives) for cr in case_results)
    fp_fn = sum(len(cr.forensic.false_negatives) for cr in case_results)
    fp_fp = sum(len(cr.forensic.false_positives) for cr in case_results)
    forensic_p = fp_tp / (fp_tp + fp_fp) if (fp_tp + fp_fp) > 0 else 0.0
    forensic_r = fp_tp / (fp_tp + fp_fn) if (fp_tp + fp_fn) > 0 else 0.0

    sf_tp = sum(len(cr.static_true_positives) for cr in case_results)
    sf_fn = sum(len(cr.static_false_negatives) for cr in case_results)
    static_r = sf_tp / (sf_tp + sf_fn) if (sf_tp + sf_fn) > 0 else 1.0

    cm_tp = sum(len(cr.correlator_true_positives) for cr in case_results)
    cm_fn = sum(len(cr.correlator_false_negatives) for cr in case_results)
    corr_r = cm_tp / (cm_tp + cm_fn) if (cm_tp + cm_fn) > 0 else 1.0

    durations = sorted(cr.timings.total_seconds for cr in case_results)
    median_dur = durations[len(durations) // 2] if durations else 0.0
    max_dur = max(durations) if durations else 0.0

    return EvalSummary(
        corpus_path=str(corpus_path),
        generated_at=datetime.now().isoformat(timespec="seconds"),
        case_count=len(case_results),
        passed_cases=sum(1 for cr in case_results if cr.passed),
        failed_cases=sum(1 for cr in case_results if not cr.passed),
        over_budget_cases=sum(1 for cr in case_results if cr.over_budget),
        forensic_tp=fp_tp, forensic_fn=fp_fn, forensic_fp=fp_fp,
        forensic_precision=forensic_p, forensic_recall=forensic_r,
        static_tp=sf_tp, static_fn=sf_fn, static_recall=static_r,
        correlator_tp=cm_tp, correlator_fn=cm_fn, correlator_recall=corr_r,
        total_wall_seconds=overall_seconds,
        median_case_seconds=median_dur,
        max_case_seconds=max_dur,
        case_results=case_results,
    )


def detect_drift(
    current: EvalSummary,
    baseline: dict,
    *,
    tolerance_recall: float = 0.0,  # any recall drop = drift
    tolerance_perf_ratio: float = 1.5,  # 50% slower = drift
) -> List[str]:
    """Compare current eval summary against a baseline JSON dict.
    Returns list of human-readable drift messages — empty list means
    no significant change."""
    drifts = []
    base_forensic_recall = baseline.get("forensic", {}).get("recall", 1.0)
    if current.forensic_recall < base_forensic_recall - tolerance_recall:
        drifts.append(
            f"forensic recall dropped: "
            f"{base_forensic_recall:.4f} → {current.forensic_recall:.4f}"
        )
    base_static_recall = baseline.get("static", {}).get("recall", 1.0)
    if current.static_recall < base_static_recall - tolerance_recall:
        drifts.append(
            f"static recall dropped: "
            f"{base_static_recall:.4f} → {current.static_recall:.4f}"
        )
    base_corr_recall = baseline.get("correlator", {}).get("recall", 1.0)
    if current.correlator_recall < base_corr_recall - tolerance_recall:
        drifts.append(
            f"correlator recall dropped: "
            f"{base_corr_recall:.4f} → {current.correlator_recall:.4f}"
        )
    base_total_seconds = baseline.get("perf", {}).get("total_wall_seconds", 0.0)
    if base_total_seconds > 0:
        ratio = current.total_wall_seconds / base_total_seconds
        if ratio > tolerance_perf_ratio:
            drifts.append(
                f"total wall time regression: "
                f"{base_total_seconds:.1f}s → {current.total_wall_seconds:.1f}s "
                f"({ratio:.2f}× slower)"
            )
    return drifts


def write_eval_reports(summary: EvalSummary, output_dir: Path) -> Tuple[Path, Path]:
    """Write JSON + Markdown summary."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    json_path = output_dir / f"eval-{stamp}.json"
    md_path = output_dir / f"eval-{stamp}.md"
    json_path.write_text(
        json.dumps(summary.to_dict(), indent=2, default=str),
        encoding="utf-8",
    )
    md_path.write_text(_render_markdown(summary), encoding="utf-8")
    return json_path, md_path


def _render_markdown(summary: EvalSummary) -> str:
    lines = []
    lines.append(f"# agent-audit eval report")
    lines.append("")
    lines.append(f"_generated {summary.generated_at}_")
    lines.append("")
    lines.append(f"- Corpus: `{summary.corpus_path}`")
    lines.append(f"- Cases: {summary.case_count}")
    lines.append(f"- Passed end-to-end: {summary.passed_cases}")
    lines.append(f"- Failed: {summary.failed_cases}")
    lines.append(f"- Over runtime budget: {summary.over_budget_cases}")
    lines.append("")

    lines.append("## Forensic side (scan)")
    lines.append("")
    lines.append(f"- TP: {summary.forensic_tp}")
    lines.append(f"- FN: {summary.forensic_fn}")
    lines.append(f"- FP: {summary.forensic_fp}")
    lines.append(f"- Precision: {summary.forensic_precision:.4f}")
    lines.append(f"- Recall: {summary.forensic_recall:.4f}")
    lines.append("")

    lines.append("## Static side (scan-project)")
    lines.append("")
    lines.append(f"- TP: {summary.static_tp}")
    lines.append(f"- FN: {summary.static_fn}")
    lines.append(f"- Recall: {summary.static_recall:.4f}")
    lines.append("")

    lines.append("## Cross-mode side (correlators)")
    lines.append("")
    lines.append(f"- TP: {summary.correlator_tp}")
    lines.append(f"- FN: {summary.correlator_fn}")
    lines.append(f"- Recall: {summary.correlator_recall:.4f}")
    lines.append("")

    lines.append("## Performance")
    lines.append("")
    lines.append(f"- Total wall time: {summary.total_wall_seconds:.1f}s")
    lines.append(f"- Median per-case: {summary.median_case_seconds:.2f}s")
    lines.append(f"- Max per-case: {summary.max_case_seconds:.2f}s")
    lines.append("")

    if summary.failed_cases > 0 or summary.over_budget_cases > 0:
        lines.append("## Issues")
        lines.append("")
        for cr in summary.case_results:
            if not cr.passed:
                lines.append(f"### `{cr.case_id}` — FAILED")
                if cr.forensic.false_negatives:
                    fns = ", ".join(
                        f"{fn.rule_id}:{fn.severity}"
                        for fn in cr.forensic.false_negatives
                    )
                    lines.append(f"- forensic missing: {fns}")
                if cr.forensic.false_positives:
                    fps = ", ".join(
                        f"{fp.rule_id}:{fp.severity}"
                        for fp in cr.forensic.false_positives
                    )
                    lines.append(f"- forensic extra: {fps}")
                if cr.static_false_negatives:
                    fns = ", ".join(
                        f"{fn.rule_id}:{fn.severity}"
                        for fn in cr.static_false_negatives
                    )
                    lines.append(f"- static missing: {fns}")
                if cr.correlator_false_negatives:
                    fns = ", ".join(
                        f"{fn.correlator}:{fn.severity}"
                        for fn in cr.correlator_false_negatives
                    )
                    lines.append(f"- correlator missing: {fns}")
                lines.append("")
            elif cr.over_budget:
                lines.append(f"### `{cr.case_id}` — OVER BUDGET")
                lines.append(
                    f"- runtime {cr.timings.total_seconds:.2f}s "
                    f"vs budget {cr.runtime_budget_seconds}s"
                )
                lines.append("")

    return "\n".join(lines)
