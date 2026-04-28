# Contributing

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Before Opening a PR

Run the test suite:

```bash
python3 -m pytest -q tests
```

If you changed scanning, reporting, or rule-loading behavior, also run the
relevant smoke workflow locally:

```bash
python3 -m agent_audit.cli packs
python3 -m agent_audit.cli benchmark --corpus ./benchmarks/incident-corpus -y
```

## Change Expectations

- add or update tests with behavior changes
- keep new files ASCII unless there is a strong reason not to
- prefer small, focused PRs
- document user-visible CLI or report changes in `CHANGELOG.md`

## Detector Work

When changing a detector or lexicon:

- include at least one regression test
- note expected precision/recall tradeoff in the PR description
- avoid changing golden labels and detector logic in the same PR unless the reason is explicit

## Security Reports

Do not open public issues for undisclosed vulnerabilities. Use `SECURITY.md`.
