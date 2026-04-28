# Incident Corpus

Curated benchmark corpus for `agent-audit`.

Each case is a synthetic reconstruction of a published incident report, stored
as:

- `case.json` — metadata and golden labels
- `session.jsonl` — the session transcript template
- optional `project/` — files copied into the case cwd before scanning
- optional `agent_home/` — files copied into the agent home before scanning

Golden labels are exact `(rule_id, severity)` pairs. The benchmark scores:

- precision = exact matched labels / predicted labels
- recall = exact matched labels / expected labels

Use it in CI or on release candidates:

```bash
agent-audit benchmark --corpus ./benchmarks/incident-corpus
agent-audit benchmark --corpus ./benchmarks/incident-corpus --output ./reports
pytest tests/test_benchmark_corpus.py -q
```

Suggested intake workflow for new public incidents:

1. Save the public source in `source_url` or `source_notes`.
2. Prefer normalized incident digests from your local incident warehouse
   when available, for example:
   `sample_data/*incidents*.json`, `state/live/published_archive.json`,
   and `runs/*/publishable_incidents.json`.
3. Reconstruct the minimal session that preserves the failure mode.
4. Add every detector label that should fire, not just the headline one.
5. Keep the fixture narrow enough that extra labels are intentional.
6. Prefer permalink posts from `https://t.me/aiaifail` when a Telegram post is
   the primary public write-up.
