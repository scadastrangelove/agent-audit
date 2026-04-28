from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT / "src"))

from agent_audit.benchmark import load_corpus, run_benchmark  # noqa: E402


def test_curated_benchmark_corpus_matches_exact_labels():
    corpus = ROOT / "benchmarks" / "incident-corpus"
    cases = load_corpus(corpus)
    assert len(cases) >= 6

    summary = run_benchmark(corpus)

    assert summary.failed_cases == 0
    assert summary.passed_cases == summary.case_count
    assert summary.false_negatives == 0
    assert summary.false_positives == 0
    assert summary.precision == 1.0
    assert summary.recall == 1.0
