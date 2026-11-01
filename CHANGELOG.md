<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# Changelog

## Unreleased

- Cache session-rule anchors by regex content and flags, with bounded storage,
  so collected regex objects cannot leave incorrect anchors for later patterns.

## 0.21.0 (released 2026-05-08)

Phase 5.2 release: A5 Cisco YARA integration. Second deferred-list
item from v0.19's roadmap. Adds a static-side detection layer for
MCP manifests using Cisco AI Defense's vendored YARA rule pack.

### A5 — Cisco mcp-scanner YARA rules vendored + integrated

Cisco AI Defense's [mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
ships ~10 production-quality YARA rules targeting MCP **tool surface
text**: tool names, descriptions, prompt definitions, inputSchema
fields. These are the strings the LLM ultimately reads when deciding
what an MCP tool does — so injection / poisoning / exfiltration
patterns embedded there are the highest-impact attack surface for
MCP-using agents.

mcp-scanner runs against **live MCP servers** (connect, list_tools,
scan results). agent-audit can't always do that — analysis is
offline, sometimes air-gapped. But the same content also lives in
**discovered manifests** (mcp.json, claude_desktop_config.json,
.cursor/mcp.json, .vscode/mcp.json), which `scan-project` already
enumerates as `audit_surface=mcp_manifest`.

A5 loads the vendored YARA rule set and applies it to manifest
content — both raw and structured (extracts tool defs from JSON,
scans name + description + inputSchema fields explicitly so YARA
matches at the right granularity).

### Vendored rule pack

Located at `src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/`:

  - `yara_rules/` — 10 .yara files copied verbatim from
    cisco-ai-defense/mcp-scanner @ HEAD on 2026-05-08
  - `LICENSE` — Apache 2.0 attribution preserved
  - `README.md` — documents the vendoring, mapping to agent-audit
    rule_ids, refresh procedure

Coverage by rule:

  | Rule file | Threat type | Default severity |
  |---|---|---|
  | `code_execution.yara` | Code execution / RCE | medium |
  | `coercive_injection.yara` | Coercive injection | high |
  | `command_injection.yara` | Shell command injection | critical |
  | `credential_harvesting.yara` | API keys, SSH keys, env vars exfil | critical |
  | `data_exfiltration.yara` | Network exfil patterns | critical |
  | `prompt_injection.yara` | System-prompt override / role redefine | high |
  | `script_injection.yara` | XSS, JS injection | medium |
  | `sql_injection.yara` | SQL injection patterns | critical |
  | `system_manipulation.yara` | OS command, privilege escalation | high |
  | `tool_poisoning.yara` | MCP tool description poisoning | high |

Severity mapping derives from each rule's `threat_type` and
`classification` meta fields. See `_threat_to_severity()` in
`mcp_yara_scanner.py` for the table. Conservative defaults — Cisco's
own pipeline applies LLM-as-judge on top of YARA before deciding
severity, and we don't have that here, so we err toward MEDIUM
confidence on every A5 finding regardless of severity.

### License compliance

Cisco mcp-scanner is **Apache 2.0**. Vendoring Apache 2.0 into MIT
is permitted with attribution — agent-audit preserves the LICENSE
file in the vendored directory, includes attribution in the
README, and references the upstream repo in every A5 finding's
`references` field.

### Optional dependency: `yara-python`

`pip install agent-audit[yara]` installs `yara-python>=4.5`. The
base install does NOT include yara — keeps the lean install path
unaffected. When yara is missing:

  - Module `mcp_yara_scanner` imports cleanly (no top-level yara import)
  - `is_available()` returns False
  - `scan_manifest()` returns a result with `error` set, no findings
  - `scan-project` integration silently skips A5 — no errors, no crashes

Tested both code paths in the test suite. CI without yara installed
still passes the full regression.

### Integration: scan-project hook

`project_scanner._scan_file()` now calls `mcp_yara_scanner.scan_manifest()`
on files classified as `audit_surface=mcp_manifest`. Each YARA match
becomes a Finding with:

  - `rule_id`: `A5.cisco-yara-<rule-name>` (one per Cisco rule file —
    distinct IDs so an auditor sees which Cisco pattern fired)
  - `severity`: derived per the threat_type table above
  - `confidence`: MEDIUM (uniform across A5 — pattern matches are not
    semantic certainty)
  - `evidence[*].source`: the manifest path
  - `evidence[*].snippet`: matched-string snippets (up to 3, 200 chars
    each) so the auditor can locate the exact problem without re-running
    YARA
  - `references`: ASAMM AI-04 (tool poisoning), C2 (credential exfil),
    OWASP MCP-Tool-Poisoning, link to upstream Cisco repo

A5 findings co-fire with existing aguara/credential rules where
patterns overlap — different detectors catching the same problem from
different angles. Useful belt-and-suspenders, not a duplicate-finding
problem.

### Manifest field extraction

`mcp_yara_scanner._extract_scannable_fields()` parses 4 known MCP
manifest shapes:

  1. **Anthropic claude_desktop_config / Cursor mcp.json**:
     `{"mcpServers": {"<name>": {"command": ..., "args": [...], "env": {...}}}}`
     Extracts: server name, command, each arg, each env value
  2. **Generic mcp.json with embedded tools**:
     `{"tools": [{"name": ..., "description": ..., "inputSchema": ...}]}`
     Extracts: tool name, description, inputSchema-as-JSON
  3. **Prompts array**: `{"prompts": [{"name": ..., "description": ...}]}`
  4. **Top-level instructions**: `{"instructions": "..."}`

Field extraction is structural — YARA matches at field granularity
not whole-file blob. This means findings carry useful field paths
(e.g. `tools[2].description`) instead of opaque "matched somewhere".

Non-JSON manifests (corrupt or unrecognized format) fall back to
raw-text scanning so we don't lose coverage on edge cases.

### Tests — 31 new

`tests/test_v0_21_a5_yara_scanner.py`:

  - Availability + compile (3 tests; 2 marked `requires_yara`)
  - Severity mapping (13 parametrized cases)
  - Manifest field extraction (6 tests covering all 4 shapes +
    pathological inputs)
  - End-to-end scan_manifest (5 tests: benign zero-finding, credential
    exfil firing, unreadable file, non-JSON fallback, field-path
    recording)
  - yara-missing graceful path (1 test, monkeypatch)
  - scan-project integration (3 tests: A5 fires on malicious manifest,
    A5 silent on benign, A5 silent without yara installed)

### Incident corpus — 3 cases

  - `a5-mcp-manifest-credential-exfil-2026-05` (positive, 2 critical
    findings expected) — manifest with .env + AWS_SECRET_ACCESS_KEY +
    curl-to-attacker exfil pattern. Both `credential_harvesting` and
    `data_exfiltration` Cisco rules fire.
  - `a5-mcp-manifest-tool-poisoning-2026-05` (positive, 1 critical
    finding expected) — manifest with `<IMPORTANT>...curl|bash...</IMPORTANT>`
    pattern. Cisco's `command_injection` rule catches it. Note: the
    `tool_poisoning` rule itself targets more specific phrases like
    "also collects" / "during processing extract" — our fixture
    triggers `command_injection` instead. Case description documents
    why.
  - `a5-mcp-manifest-benign-no-fire-2026-05` (negative) — weather +
    calendar + list_files manifest. Zero A5 findings expected. Locks
    the FP guard.

These join the existing 19 cases, bringing the incident corpus to
**22 cases** total.

### Eval results on full corpus (22 cases)

  - Cases passed end-to-end: 22/22
  - Forensic precision: 1.0
  - Forensic recall: 1.0
  - Static recall: 1.0 (was 1.0 in v0.20 with 0 expected_static_findings;
    now 1.0 with 3 of the 22 cases declaring expected_static_findings)
  - Correlator recall: 1.0
  - Total wall: 4.0s

### Status snapshot

Test count: 867 passing (+31 from A5), 1 skipped. All 4 validators
green. Eval template extended: cases can now declare
`expected_static_findings` against A5 rule_ids and the harness scores
them per the v0.19 contract.

### Phase 5 status

  - ✅ N2 (v0.20.0)
  - ✅ A5 (v0.21.0)
  - ⏸ A4 (TruffleHog regex) — still gated on AGPL-vs-MIT counsel call
  - ⏸ A6 (mcp-audit external) vs N2-extended — data-driven decision
    after multi-MCP-server bundle eval lands
  - ⏸ C2 (Semgrep) — descoped further now that A5 covers MCP source-side.
    May get re-evaluated as user-instructions ("run semgrep separately")
    rather than vendored.

### Refresh / upgrade procedure

To pull newer Cisco YARA rules (they ship periodically):

```bash
cd /tmp && rm -rf mcp-scanner
git clone --depth 1 https://github.com/cisco-ai-defense/mcp-scanner.git
cp /tmp/mcp-scanner/mcpscanner/data/yara_rules/*.yara \
   src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/yara_rules/
cp /tmp/mcp-scanner/LICENSE \
   src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/LICENSE
agent-audit eval  # confirm corpus still passes
```

The vendored README documents this. Refresh cadence is maintainer's
choice — Cisco rules are stable enough that we don't need automation
yet.



Phase 5.1 release: N2 cross-server toxic flow detector. First step in
the deferred conditional-rule-pack roadmap from v0.19.

### N2 — cross-server toxic flow detector

Detects when content from one MCP server's tool result flows into a
**different** MCP server's tool argument, where the intermediate
content carries injection markers, secret references, or destructive
command syntax. Captures a class of indirect prompt injection that
neither single-server detectors nor inventory-based correlators see —
the attack lives in the cross-tool data plumbing, not in either server
individually.

Pattern:

  T_n:   tool_use     server_a__read_thing
  T_n+1: tool_result  contains <suspicious patterns>
  T_n+2: tool_use     server_b__write_thing(... content from T_n+1 ...)

Severity escalation by payload class:

  - `destructive_command` (rm -rf, drop database, etc.) → critical
  - `injection_marker` (ignore previous instructions, etc.) → high
  - `secret_reference` (.env, API keys, etc.) → high + medium confidence
    + `needs_llm_verification=True` (ambiguous on its own; flag for
    manual review)

False-positive guards built in:

  - **Same-server flow**: github__read → github__write doesn't fire,
    only cross-server pairs. Same-surface workflows aren't the attack
    pattern N2 targets.
  - **Native-tool flow**: Bash → Bash, Read → Edit, etc. don't fire
    — these aren't crossing MCP server boundaries.
  - **Content-flow proof required**: detector requires ≥32-char
    contiguous substring overlap between source result and sink args.
    Eliminates pure heuristic noise — when content actually flowed,
    we can show the exact substring as evidence.
  - **Per-pair de-dup**: one (server_a, server_b) pair fires once per
    session, not once per hop. Long attacks don't flood findings.
  - **Forward window of 20 events**: flows past 20 turns are unlikely
    to be causally related, regardless of content overlap.

Integration:

  - New module `src/agent_audit/detectors/cross_server_toxic_flow.py`
    — pure session-rule detector, no inventory dependency, registers
    via the standard `register_session_rule()` path.
  - Server-name extraction via `_extract_server_name()` recognizes
    Anthropic's `server__tool` convention plus colon and dot
    separators. Native tools (Bash, shell, exec_command, Read, Edit,
    etc.) explicitly excluded so they don't accidentally show as
    "server" via false separator matches.
  - References ASAMM AI-06 (indirect prompt injection), AI-04
    (persistence write), C2 (credential exfil); OWASP LLM01:2025;
    OWASP Agentic Threat (cross-tool data flow).

36 new tests in `tests/test_v0_20_cross_server_toxic_flow.py`:

  - Server name extraction (10 cases incl. natives, malformed inputs)
  - Payload classification (5 cases incl. priority handling)
  - Content-flow detection (4 cases incl. short-source guard)
  - End-to-end detection (10 scenarios incl. all 3 payload classes,
    same-server negative, native-tools negative, no-overlap negative,
    dedup test, registration test, short-payload negative)

3 new incident-corpus cases:

  - `n2-gmail-to-github-injection-2026-05` (high) — classic injection
    flow, demonstrates co-firing with `atr.prompt-injection.system-
    prompt-override-injection-via-mcp-tool` (legitimate; both detectors
    catch the same pattern from different angles)
  - `n2-slack-to-shell-destructive-2026-05` (critical) — destructive
    command escalation via shell-mcp
  - `n2-no-fire-on-same-server-flow-2026-05` (negative) — false-
    positive guard for benign cross-server content (large content
    overlap but no payload markers → no fire)

### Eval test bound update

`test_evaluate_corpus_on_real_incident_corpus` updated from `==16` to
`>=16` so the v0.19 baseline is preserved as a lower bound while
allowing v0.20+ cases to be added without rewriting the test on every
release. Equality with `passed_cases` ensures all cases must pass.

### Status snapshot

Test count: 836 passing (+36 from N2), 1 skipped. All 4 validators
green. Eval on incident-corpus: 19 cases, 19 passed, forensic
precision 1.0, recall 1.0, total wall 3.7s.

### Phase 5 status — what remains

Per the v0.19 deferred-list, four conditional rule packs are still
parked. v0.20 ships N2 only; each remaining item gets its own
incremental release after eval-first validation:

  - **A5 (Cisco mcp-scanner with YARA)** — pending session for
    yara-python optional dep + Cisco rule pack vendoring + 2-3 corpus
    cases with MCP server source
  - **A6 (mcp-audit external) vs N2-extended** — data-driven decision
    after we measure N2 on real bundles; if N2 covers the surface,
    drop A6
  - **A4 (TruffleHog regex)** — gated on AGPL-vs-MIT counsel call
  - **C2 (Semgrep)** — paired with A5 outcomes; less differentiated
    if A5 covers MCP server source already

The eval harness shipped in v0.19 + N2 cases shipped in v0.20 set the
template: every new rule pack must arrive with corpus cases and
measurable outcomes before merge. This avoids re-introducing ПФЗ
items from the v0.17/v0.18 hypothesis audit.



Real-data hardening release. Driven by maintainer's full-rerun bundle
(forensic + scan-project + cross-mode + benchmark + tool-pinning passes
on a real `~/.codex/sessions/` and `~/.claude/projects/` populated tree)
which surfaced one critical bug, exposed perf bottlenecks at scale, and
gave us empirical data to refine v0.18.x architectural choices.

### Critical bug fix — cross-mode produced 0 aggregates on real bundles

`_findings_by_session` in `src/agent_audit/cli.py` only checked
`f.get("session_id")` at the top level of finding dicts. In saved scan
JSON, session_id lives **inside** the `evidence` array, never at top
level. Result: every finding from a saved bundle ended up under the
empty-string key, the linker never saw them, and cross-mode emitted 0
aggregate records on every real bundle even when matching dynamic
findings + risk tags BOTH fired.

Confirmed via maintainer's bundle: 5 of 6 risk-tagged sessions had
matching dynamic findings (`C3.autonomy-with-exfil-chain`,
`AI-06.indirect-prompt-injection-vector`, `AG-04.destructive-without-backup`)
but cross-mode produced 0 aggregates. Direct linker call on the same
data produced correct records — bug was specifically in this CLI helper.

The v0.18.3 inline cross-mode path (in `scanner._build_inline_cross_mode_report`)
was always correct because it reads from `Finding.evidence[*].session_id`
directly. Only the standalone `cross-mode` subcommand was affected.

Fix: helper falls back to `evidence[*].session_id` when top-level is
absent. 2 regression tests added (`test_findings_by_session_reads_session_id_from_evidence`,
`test_findings_by_session_prefers_top_level_session_id`).

Diagnostic addition: when cross-mode CLI exits with `aggregate_records=0`
but findings WERE present and sessions WERE processed, console emits a
`[yellow]Note:[/yellow]` explaining possible causes — would have caught
this class of bug immediately.

### Autodetect fixture-corpus shape (Phase 2)

The v0.18.1 hardcoded vendor-prune of `benchmarks/`, `fixtures/`,
`test_data/`, `test_fixtures/` over-corrected: it dropped legitimate
signal on projects where `benchmarks/` carries product content (e.g.
`benchmarks/agent-tasks/AGENTS.md` for an RL training repo). v0.18.3
made it opt-in via `--vendor-prune`, but that left agent-audit's own
dev tree producing 6 active risk tags by default — accurate but noisy.

v0.19 adds shape-aware autodetection: when a directory's immediate
children look like a fixture corpus (≥2 child dirs each containing a
`case.json` marker), the subtree is pruned. This catches agent-audit's
own `benchmarks/m2-calibration-corpus/c*/` without affecting projects
where `benchmarks/` doesn't carry the fixture-shape marker.

Components added in `src/agent_audit/cross_mode/inventory.py`:
- `_FIXTURE_CASE_DIR_PATTERN` regex matches `c1`, `c1-foo`, `case-1`,
  `tc-1`, etc. (case-insensitive)
- `_is_fixture_corpus_root(dirpath, dirnames)` checks for ≥2 children
  with `case.json` markers
- `_walk_repo_files()` integrates the autodetect into the os.walk
  pruning step

Verified on agent-audit dev tree: 0 files yielded from
`benchmarks/m2-calibration-corpus/c*/`. The four documentation files
(`README.md`, `CHANGELOG.md`, etc.) still surface as `has_instruction_files`
and one `has_broad_action_without_approval` — that's accurate and
intentional (agent-audit is a security tool documenting these patterns).

26 new tests in `tests/test_v0_19_autodetect_fixture_shape.py`:
pattern matching (12), corpus-shape detection (4), integration with
inventory walker (3), regression guard for self-similar tree (1).

### Performance hardening — scan-session inventory trust (Phase 3)

Real bundle had 252 of 304 sessions (83%) resolving to a single repo.
Each lookup paid for full directory walk + classify + fingerprint
computation, even on a hot canonical cache, because the cache key
requires the fingerprint. On maintainer's machine: cross-mode wall
time was 277s, almost entirely repeated walks of the same tree.

v0.19 adds explicit "scan session" context. Within
`enter_scan_session()` / `exit_scan_session()`, repeat lookups for
the same `(repo_root, vendor_prune)` skip the canonical fingerprint
validation entirely and return the path-keyed in-memory entry.
Filesystem state is assumed stable for the duration of one scan
invocation — a tradeoff explicitly documented in the docstring.

Outside the scan-session context, the canonical `_CACHE` continues
to validate fingerprints per call. Tests confirm correctness preserved:
filesystem changes after `exit_scan_session()` invalidate cache.

`scanner.scan()` wraps its body in try/finally calling
`enter_scan_session()` and `exit_scan_session()` — guaranteed cleanup
even on exception, otherwise subsequent calls would silently get
stale inventories.

Measured on synthetic 200-file repo, 252 lookups:
- Without trust: 3.25s (12.9ms each)
- Canonical cache only: 3.08s (12.2ms each — barely better, all the
  cost is the walk)
- With scan-session trust: 0.02s (0.084ms each)

145× speedup on the in-session common case. Real-bundle extrapolation:
277s cross-mode → ~30-50s.

9 new tests in `tests/test_v0_19_scan_session_trust.py`: enter/exit
state, cache short-circuit, vendor_prune key separation, exception
safety, integration with scanner.scan().

### Real-data evaluation harness — `agent-audit eval` (Phase 4)

The v0.18.x hypothesis audit identified 5 ПФЗ items (production claims
unverified on real data). v0.19 institutionalizes the validation
discipline by adding an `eval` subcommand that runs the full pipeline
end-to-end on a corpus and produces a comparable artifact across runs.

Pipeline per case:
1. Materialize the case into a workspace dir (outside `/tmp/` to avoid
   AG-04 ephemeral filter false-skip — see "Benchmark materialization
   path fix" below)
2. Run `scan()` with cross-mode enabled → forensic findings + cross_mode_report
3. Run `scan-project` on the materialized project subtree → static findings
4. Score against the case's `expected_findings`, `expected_static_findings`,
   `expected_correlators` (last two are v0.19 additions, optional)
5. Record per-stage timings; flag cases over `expected_runtime_budget_seconds`

Output:
- `eval-{stamp}.json` — full structured summary
- `eval-{stamp}.md` — human-readable summary with pass/fail breakdown
  and issue list

CLI features:
- `--baseline <prior-eval-json>` — drift detection vs a prior run.
  Flags recall drops (any drop = drift) and perf regressions (>1.5×
  default tolerance)
- `--ci` — terse output, exit non-zero on failure or drift. Designed
  for CI gates
- `--corpus <path>` — defaults to `benchmarks/incident-corpus/`

Module: `src/agent_audit/eval_harness.py` — `evaluate_corpus()`,
`detect_drift()`, `write_eval_reports()`, dataclasses for case results
and summary. Imports `scan` from scanner and `scan_project` from
project_scanner; no new external dependencies.

15 new tests in `tests/test_v0_19_eval_harness.py`: scoring (5),
drift detection (6), end-to-end (1, marked slow), schema migration (1).

Run on incident-corpus: 16 cases, 16 passed end-to-end, total wall
3.2s. Forensic precision/recall 1.0/1.0. Static and correlator recall
both 1.0 (no v0.19 expected_static or expected_correlator fields yet
on the existing cases — these are additive migrations for future
labeling work).

### Incident corpus label refinement

The v0.17/v0.18 hypothesis audit identified 4 cases marked FAIL by
the benchmark whose detection was actually legitimate but unlabeled.
v0.19 adds the missing labels with explicit `note` fields documenting
why the labeling was incomplete:

- `comment-and-control-github-actions-prompt-injection-2026-04`:
  added `atr.privilege-escalation.shell-metacharacter-injection-in-tool-arguments:critical`
  (legitimate match on `cat .env | curl` exfil chain)
- `github-mcp-prompt-injection-private-repo-exfil-2025-05`:
  same shell metachar injection pattern
- `ox-mcp-config-mutation`: shell metachar injection inside MCP
  config write
- `ox-flowise-wrapper-bypass`: added
  `atr.excessive-autonomy.agent-resource-exhaustion-detection:high`

Each case marked with `v019_label_refinement: true` for traceability.
Benchmark now reports 16/16 passed, precision 1.0, recall 1.0 (was
12/16, precision 0.875, recall 1.0).

### Benchmark materialization path fix

`benchmark.run_benchmark()` previously used `tempfile.TemporaryDirectory()`
without a `dir=` arg — defaulting to `/tmp/` on Linux and
`/var/folders/` on macOS. The destructive-without-backup detector
treats `/tmp/*` paths as ephemeral and silently skips findings there.
Result: the same benchmark code produced **divergent** results between
maintainer's macOS run (PASS) and Linux CI runs (FAIL).

Fix: workspace lives under `$HOME/.cache/agent-audit/` consistently.
Cases that destroy materialized files inside the workspace fire AG-04
as their session log records, which is what the corpus actually
documents. Cross-platform consistent.

### Hypothesis audit follow-through

`docs/v017-v018-hypothesis-audit.md` items resolved this release:

- 4 of 4 REFUTED items now CONFIRMED-fixed (perf, test suite from
  v0.18.1; DetectionMode plumbing, vendor-prune defaults from v0.18.3;
  benchmark materialization, cross-mode CLI bug from v0.19)
- 5 ПФЗ items now have a path to validation: the `eval` subcommand
  produces measurable real-data outcomes for each pipeline stage.
  Future cases adding `expected_static_findings` and
  `expected_correlators` directly close the corresponding ПФЗ
  rows. Current eval baseline (16 cases, 1.0 recall on all three
  pipelines) becomes the regression guard.

Test count after v0.19: 800 passing, 1 skipped. All 4 reference
validators (ATLAS, OWASP MCP, OWASP Agentic, AVID) green.

### Deferred to v0.20+

The v0.19 scope discussion enumerated 5 conditional rule pack items
(A5 Cisco mcp-scanner with YARA, A6/N2 cross-server toxic flow, A4
TruffleHog regex, C2 Semgrep, additional D-suite benchmarks). All
deferred — adding new rule packs without real-data validation
against them would create new ПФЗ items, exactly what the audit
discipline aims to prevent. v0.20 plan: ship rule pack → add eval
cases → measure → release. The eval harness shipped in v0.19 is
the prerequisite that makes this discipline tractable.



This release combines two follow-ups from the v0.18.1 real-data run:
the DetectionMode plumbing fix that v0.18.1 hypothesis audit had marked
REFUTED-pending, AND a reversal of two architectural decisions that
v0.18.1 had over-corrected.

### DetectionMode plumbing through `scan()` (v0.18.2 track)

- `scanner.scan()` accepts `mode: DetectionMode = BALANCED` kwarg and
  forwards it to `run_session_rules()` and `run_config_rules()`.
- CLI passes `detection_mode` value (mapped from `--mode {conservative,
  standard,full}`) through to `scan()`. Previously the value was built
  but never delivered to the rule engine — `--mode full` reached
  scope decisions and verifier-auto-on, but mode-aware rules
  (`adjacent_repo_probe`, `ssh_key_probe`) only got the default
  BALANCED inside the rule path.
- 5 new tests in `tests/test_v0_18_2_changes.py` lock the propagation.

### Vendor-prune defaults reversed (v0.18.2 track)

The v0.18.1 patch hardcoded `benchmarks/`, `fixtures/`, `test_data/`,
`test_fixtures/` directories AND README/CHANGELOG/etc. as skipped from
inventory walking. That fix removed false-positives on agent-audit's
own dev tree, but at the cost of silently dropping legitimate signal
on any other project where benchmarks/ carries real product content
(e.g. agent-rl `benchmarks/agent-tasks/AGENTS.md`,
mcp-server-benchmark `benchmarks/scenarios/CLAUDE.md`).

v0.18.3 corrects this:

- `_SKIP_DIRS` split into `_ALWAYS_SKIP_DIRS` (true vendor: `.git`,
  `node_modules`, `.venv`, etc.) and `_OPTIONAL_SKIP_DIRS`
  (`benchmarks`, `fixtures`, `test_data`, `test_fixtures`).
- `build_repo_signal_inventory()` accepts `vendor_prune: bool = False`.
  Default scans everything that isn't unambiguous third-party content.
- `_DOCUMENTATION_FILENAMES` (README/CHANGELOG/etc.) now opt-in: only
  excluded when vendor_prune is on. Default treats README.md as an
  instruction surface — many projects use it as their primary agent
  contract.
- New CLI flag `--vendor-prune` (off by default) on both
  `agent-audit scan` and `agent-audit cross-mode`. Turn on for
  security-tooling repos whose meta-content trips up tag derivation.
- Inventory cache key includes vendor_prune so a repo scanned with
  both flag values gets two distinct cache entries.
- Calibration cases c5/c7/c13 reverted to original expected_repo_tags
  (README scanned by default again).
- 11 new tests in `tests/test_v0_18_2_changes.py` lock the new defaults.

Verified on agent-audit dev tree:
- Default (vendor_prune=False): 6 active tags fired, 25 instruction
  files. Honest reflection that this repo is a security tool
  documenting adversarial patterns.
- Opt-in (vendor_prune=True): 1 active tag, 2 instruction files.
  Reduces noise for users who specifically want filtered view.

### Cross-mode runs by default in `scan()` (v0.18.3 track)

This reverses the v0.18.0 D4 "separate subcommand" decision once
cross-mode proved stable. Two-step UX (`scan` then `cross-mode`)
created friction without commensurate benefit; running cross-mode
inline reuses Phase 1 inventory (already populated during the scan
loop) so there's no perf cost to integration.

- `scanner.scan()` accepts `cross_mode: bool = True`. When True (default)
  and at least one session was processed, builds cross-mode report
  inline and stores on `result.cross_mode_report`.
- New `_build_inline_cross_mode_report()` helper in scanner.py mirrors
  the JSON shape produced by the standalone CLI subcommand. Reuses
  `result.repo_inventories` so no second walk; reads dynamic findings
  from `result.findings` directly so no JSON roundtrip.
- D5 boundary preserved: findings have already been filtered through
  `_apply_project_config()` during the scan loop, so the linker
  honors user suppressions without consulting suppression machinery.
- Cross-mode failure does NOT break scan: caught and recorded as
  scan error (`result.errors`), then continues.
- `write_reports()` produces `cross-mode-{stamp}.json` and
  `cross-mode-{stamp}.md` alongside the main audit files when
  `cross_mode_report` is populated. Same JSON shape as the standalone
  CLI subcommand for downstream tooling consistency.
- New CLI flag pair `--cross-mode / --no-cross-mode` on `scan`,
  default ON.
- Standalone `cross-mode` subcommand stays for rerun-on-saved-bundle
  workflows (re-run against existing forensic bundle without
  re-scanning agent home, pair with --scan-project post-hoc, test
  cross-mode behavior changes against stable bundles). Help text
  updated to reflect the new role.
- 15 new tests in `tests/test_v0_18_3_scan_cross_mode_default.py`
  cover signature, integration, write_reports, CLI flag plumbing.

### Verbose progress mode

Replaces the v0.18.0 D4 rationale that "separate subcommand keeps
debugging boundary explicit". With cross-mode integrated, debugging
who-took-how-long stays observable via timestamped progress messages.

- `scan()` accepts `verbose: bool = False` kwarg. When True, progress
  callback receives messages prefixed with `[HH:MM:SS]` so a maintainer
  can see exactly when each phase started.
- New CLI flag `--verbose / -v` on `scan`. When set, console progress
  output gains timestamps; cross-mode duration is logged at completion.
- Cross-mode block in `scan()` records `cross_mode_complete` audit log
  entry with duration_ms, aggregate_records, and tag_applications counts.
- Per-step durations addressable via the audit log even without -v.

### Hypothesis audit follow-through

`docs/v017-v018-hypothesis-audit.md` items resolved this release:

- "DetectionMode plumbing — REFUTED → fixed in v0.18.3" (was scheduled
  v0.18.2; landed in v0.18.3 combined release)
- "M2 Phase 1 tag selectivity — REFUTED → fixed in v0.18.1, REVISED
  in v0.18.3" (the v0.18.1 fix was overcorrected; v0.18.3 makes prune
  opt-in)

ПФЗ items remain unchanged: 5 production claims still need real-data
validation (N1 tool-pinning, M3 NOVA evaluator, scan-project adapter,
cross-mode TPR/FPR, D2/D3 benchmark numbers). Most actionable next:
real-data evaluation harness (Variant B from the v0.18.1 → v0.19+
roadmap discussion).



Patch release driven by a real-data run on a maintainer's `~/.codex/sessions/`
that surfaced two distinct production defects: a forensic scan that stalled
20+ minutes on a single 41MB Codex rollout, and an inventory walker that
fired all 5 risk tags on 226 of 276 sessions (82%) when those sessions
resolved to the agent-audit dev checkout itself. Both are addressed here.
A separate hypothesis audit (`docs/v017-v018-hypothesis-audit.md`) was
written alongside this release to inventory which v0.17 + v0.18 claims
were CONFIRMED, ПФЗ (assumed plausible without empirical evidence), or
REFUTED on real data.

### Performance — forensic scan no longer stalls on giant Codex rollouts

- **Hung pattern fix** in `atr.context-exfiltration.system-prompt-extraction-training-data-verbatim-replay`:
  the optional opener `(?:ignore\s+...)?[^\n]{0,80}(?:output|repeat|...)` shape
  caused the regex engine to explore every (start_pos, length) combination
  on multi-megabyte content. Profiling on 5MB content showed the pattern
  hung indefinitely (>60s with timeout). Rewritten as a single anchored
  pattern that matches "output everything above" forms directly without
  the optional-opener degenerate case. The two adjacent patterns (verbatim
  system prompt extraction, training-data cloze) already had required
  openers and were not affected.
- **Tier 1.1 — content cap (`AGENT_AUDIT_CONTENT_CAP_BYTES`, default 65536)**:
  per-event text is truncated before regex scanning. Rule patterns are
  designed for short instruction/command shapes; >64KB single events
  contain bulk content that legitimately matches nothing. Truncations
  are counted and surfaced as scan errors so coverage loss is visible.
- **Tier 1.2 — per-event SIGALRM timeout (`AGENT_AUDIT_PER_EVENT_TIMEOUT_S`,
  default 5.0, UNIX-only)**: pathological per-event regex work aborts at
  the timeout boundary; one bad event can no longer poison the rest of
  the scan. Handler installed once per session pass to avoid ~1M
  `signal.signal()` calls on big scans.
- **Tier 2 — fast-keyword anchor pre-skip**: alternation-group anchors
  (e.g. `(?:cat|curl|wget|bash)`) are extracted from each compiled regex
  at first use and cached. If none of the anchor substrings appear in
  the event text, the regex.search is skipped entirely. Conservative
  extraction keeps groups only when ALL alternatives are ≥3 chars to
  avoid false-skip on common short tokens.
- **Counters surfaced as scan errors** at scan completion via
  `consume_safeguard_counters()` integration in `scanner.scan()`. A scan
  that hit pathological content reports e.g. "Truncated 51 oversized
  event(s) to 64KB before regex" so a "0 findings" result on a giant
  session isn't silently misleading.
- **Profiled gains** on synthetic 14.8MB Codex session (close to real
  41MB stall scenario): pre-fix indefinitely hung → post-fix 37.5s.
  Maintainer's 41MB extrapolated: ~110s vs infinite. Test suite went
  from 134s → 30s as a beneficial side-effect (anchor pre-skip helps
  test runs that touch rule packs too).
- **24 new tests** in `tests/test_perf_safeguards.py`: anchor extraction
  (5), anchor application (4), content cap (5), counter snapshots (2),
  timeout machinery (3), executor integration (3), TPR preservation (1),
  perf regression guard at 5MB (1).

### Inventory walker — vendor-prune extension

- **`_SKIP_DIRS` extended** in `cross_mode/inventory.py` to include
  `benchmarks`, `fixtures`, `test_data`, `test_fixtures`. The previous
  list (`node_modules`, `.venv`, etc.) covered third-party code but not
  test fixtures. Real-data run on agent-audit's own dev checkout had
  resolved 226 of 276 sessions (82%) to that repo and fired ALL 5 risk
  tags on every one because `benchmarks/m2-calibration-corpus/c*/project/AGENTS.md`
  ships deliberate approval-bypass / fetch-surface / identity-rewrite
  language as test fixtures. Inventory now walks past those dirs.
- **`_DOCUMENTATION_FILENAMES` set added**: README.md, CHANGELOG.md,
  CONTRIBUTING.md, ROADMAP.md, SECURITY.md, LICENSE.md,
  CODE_OF_CONDUCT.md, HISTORY.md, AUTHORS.md, MAINTAINERS.md, TODO.md,
  NOTES.md. These document the project itself, not its agent
  instructions. Excluding them from instruction-surface scanning prevents
  false-positives on repos that *describe* adversarial patterns —
  security tooling like agent-audit itself, MCP frameworks, anything
  that mentions "approval bypass" or "curl | sh" in prose. Verified on
  agent-audit dev tree: tags went from 4 risk tags fired to just
  `has_instruction_files` (and instruction_file_count from 7 to 2).
- **Calibration corpus updated**: c5-clean-baseline-no-link,
  c7-dynamic-but-no-matching-tag, c13-ambient-curl-no-injection had
  `expected_repo_tags` adjusted to reflect the new behavior (README-only
  projects now produce empty tag set; final correlator outcomes
  preserved per each case's original test intent — c5/c7 stay clean
  baselines, c13 still verifies §5.2 doesn't false-fire on benign
  README curl mentions).

### Hypothesis audit — `docs/v017-v018-hypothesis-audit.md`

A new document inventories every non-trivial v0.17 + v0.18 production
claim against real-data evidence. Three categories: CONFIRMED (8 items),
ПФЗ — claimed but not empirically verified (5 items), REFUTED (4 items).

- 2 of 4 REFUTED items fixed in this patch (forensic perf, test suite perf)
- 1 of 4 REFUTED items fixed in this patch (inventory tag selectivity
  via vendor prune)
- 1 of 4 REFUTED items scheduled v0.18.2 (DetectionMode plumbing
  through `scan()` — CLI maps `--mode full` to a value but the value
  doesn't reach `run_session_rules`. Real impact small since only 2
  detectors are mode-aware, but the plumbing is broken regardless.)
- 5 ПФЗ items remain — most actionable is real-data evaluation of
  scan-project adapter and cross-mode signal flow on a non-fixture
  corpus. Synthetic calibration corpus continues to lock invariants
  but doesn't substitute for real-world TPR/FPR.



## 0.18.0 (released 2026-05-03)

Cross-mode signal flow track — see `docs/m2-cross-mode-design-draft.md`
for the full design and `docs/m2-d1-d5-decisions.md` for the settled
D1-D5 decisions.

- **M2 cross-mode CLI subcommand** (item shipped):
  - new `agent-audit cross-mode` Click subcommand at `src/agent_audit/cli.py`,
    per D4 (settled): separate subcommand over saved scan outputs,
    NOT auto-invoked inside `scan`. Keeps the execution boundary
    explicit so debugging "did the dynamic detector change, or did
    the linker change?" is a one-step bisect
  - **CLI surface**:
    - `--forensic <path>` (required) — path to a saved scan JSON
      (e.g. `audit-2026-04-01-120000.json` from `agent-audit scan
      --output DIR`)
    - `--repo-root <path>` (optional override) — force every session
      to be analyzed against this single repo regardless of session cwd
    - `--output <dir>` — writes `cross-mode-findings.json` plus
      `cross-mode-report.md`
    - `--format json|md|both` (default both)
    - `--quiet` — suppress progress output
  - **stdout summary**: counts + by-correlator breakdown
  - **JSON output**: full aggregate records, tag_applications mapped
    from rule_id back to specific finding_id, inventories per session,
    unlinkable reasons (preserves the honest-unlinkable contract)
  - **Markdown output**: human-readable summary grouped by correlator,
    with priority demotion section and unlinkable summary
  - **D5 enforcement**: linker takes findings as recorded in the JSON;
    findings already filtered through `_apply_project_config()` during
    the original scan, so the saved JSON carries already-suppressed
    state. Verified by `test_cross_mode_d5_no_resurrection_when_findings_absent`
    — empty findings list with active inventory tags produces zero
    aggregate records (the user's suppression boundary is respected)
  - **18 new tests** in `tests/test_cross_mode_cli.py` covering: help
    rendering, missing/invalid forensic input, true-link cases (c1
    fires approval_gap, markdown produced), true-negative (c5 no
    aggregates), --repo-root override (basic, with clean repo silences,
    nonexistent path errors), unlinkable handling (cwd=None graceful,
    empty sessions array), --format flag (json-only, md-only),
    --quiet suppresses progress, D5 contract, D3 tag_application
    mapping (c4 `context_demoted` tag mapped to specific finding_id)

- **M2 scan-project adapter — static findings feed correlators** (item shipped):
  - lets `scan-project` static findings serve as a SHARPER signal than
    inventory tags. Tag derivation is coarse pattern matching; a static
    finding from a rule pack is a confirmed match. Either source can
    satisfy a correlator's static-side condition; both firing produces
    stronger evidence
  - **`CorrelatorInput` extended**: new optional `static_findings:
    List[Tuple[str, str, str]]` field carrying `(rule_id, severity,
    canonical_class)` triples. Defaults to empty list — backwards
    compatible with all Phase 2 callers
  - **per-correlator canonical_class sets** added to `correlators.py`:
    - §5.1 (`_APPROVAL_GAP_STATIC_CLASSES`):
      `broad_external_action_without_approval`,
      `autonomous_execution_or_looping`
    - §5.2 (`_FETCH_SURFACE_STATIC_CLASSES`):
      `remote_fetch_or_install_expands_trust_boundary`,
      `prompt_or_instruction_override_surface`,
      `tool_or_skill_poisoning_surface`
    - §5.3 (`_IDENTITY_PERSISTENCE_STATIC_CLASSES`):
      `identity_rewrite_with_persistent_effect`,
      `agent_role_or_goal_manipulation`
    - §5.4 unchanged — educational classification is path-based, no
      rule-pack analog exists
  - **§5.3 proximity 2 invariant preserved** via new `_session_under_repo()`
    helper independent of tag check. Identity-persistence correlator
    still requires session cwd at-or-under repo root regardless of
    whether the tag or static finding fires
  - **`linker.link_signals()` extended**: optional `static_findings`
    kwarg (backwards compatible — old callers don't change). Linker
    passes the list through to correlators in `CorrelatorInput`
  - **`static_findings_to_link_input()` adapter**: projects `Finding`-shaped
    objects/dicts into the canonical triple format. Derives
    `canonical_class` via `finding_dedup.canonical_class_for_rule()`
    when not present on input — supports both the v2-bundle JSON shape
    (canonical_class always present) and older bundles
  - **CLI `--scan-project <path>` flag**: accepts a saved scan-project
    JSON. `_load_scan_project_bundle()` validator + `_extract_static_findings_by_repo()`
    attribute findings to repos via `source_paths` against
    `repos_scanned`. Single-repo override case routes all findings to
    the override path. Console summary shows `Static findings fed in:
    N across M repo(s)`
  - **JSON output additions**: `static_findings_total` (int) +
    `static_findings_provided_for_repos` (list[str]) for diagnostics
  - **evidence + supporting_signal_ids enriched**: aggregate records
    cite both inventory tag AND static finding when both fire (e.g.
    `Repo tag: has_broad_action_without_approval`,
    `Static finding: asamm.AD-02.broad-action-without-approval.skip-approval (high, class=broad_external_action_without_approval)`,
    `Dynamic finding: C3.autonomy-with-exfil-chain (high)`).
    Confidence lift counts each component → "high" when both static
    and dynamic corroborate
  - **21 new tests** in `tests/test_cross_mode_scan_project_adapter.py`:
    - adapter (5): explicit canonical_class, derivation, unknown rule
      fallback, finding-object shape, empty rule_id skip
    - correlator §5.1 (4): fires on static alone, fires with both
      sources, silent on unrelated class, accepts autonomy class
    - correlator §5.2 (2): fires on static alone, accepts alternate
      classes (override + tool-poisoning)
    - correlator §5.3 (3): fires on static alone, proximity 2 still
      required (cwd outside → no fire), accepts agent-role class
    - linker integration (3): kwarg propagates, backwards compat,
      static can satisfy without tag
    - CLI (4): end-to-end with both bundles, nonexistent path errors,
      malformed JSON errors, --scan-project optional
  - **end-to-end smoke verified**: c1 calibration project (AGENTS.md
    with bypass language) + simulated scan-project bundle (asamm.AD-02
    finding on AGENTS.md) → aggregate record citing both static finding
    and inventory tag. Severity=high, confidence=high


  - reached the §6.1 design target. Initial 7-case seed
    (c1-c7) supplemented with 13 new cases organized in three
    intentional categories
  - **TPR robustness expansion (5 cases, c8-c12)** — pattern variants
    that exercise the same correlators with different syntactic
    forms. Catches over-literal tag derivation:
    - c8: approval_gap with "auto-approve" / "no approval is needed"
      language + resource.unbounded-loop dynamic
    - c9: fetch_surface with `wget -qO- | bash` (verifies pattern set
      covers wget + bash + zsh + fish, not just curl + sh)
    - c10: identity_rewrite with "act as" / "override your default
      role" patterns
    - c11: educational variant via `tutorials/` paths triggering
      `educational_heavy` (the >50% threshold) instead of red-team
    - c12: multi-correlator — single session triggers BOTH approval_gap
      AND fetch_surface as INDEPENDENT aggregate records (verifies
      linker doesn't merge or skip)
  - **FPR robustness expansion (4 cases, c13-c16)** — close-to-positive
    but not-quite. Catches over-eager correlators:
    - c13: ambient curl|sh in legitimate README, no injection finding
      → fetch_surface NO fire (tag-only insufficient, both conditions
      required per §5.2)
    - c14: vendored SKILL.md inside `node_modules/` with bypass language
      → vendor pruning works, tags empty
    - c15: repo with only `has_skills` (benign formatter) + autonomy
      finding → approval_gap NO fire (specific tag selectivity, not
      any-skill triggers)
    - c16: identity tag + autonomy-with-exfil-chain (in §5.1's set,
      not §5.3's) → identity_persistence NO fire (per-correlator
      dynamic-side membership precise)
  - **Severity propagation expansion (4 cases, c17-c20)** — D2 and
    D3 boundary cases:
    - c17: HIGH+HIGH stays HIGH (NOT escalated to CRITICAL — the
      cap-at-max invariant downstream CI gates rely on)
    - c18: LOW + bypass tag stays LOW (cross-mode joining cannot
      raise severity even when corroboration is real)
    - c19: HIGH dangerous-recommendation in red-team repo → §5.4
      must NOT demote (severity gate ≤ medium prevents under-reporting
      of seriously bad advice)
    - c20: CRITICAL dangerous-recommendation in red-team repo → §5.4
      must NOT demote (gate holds at upper end of severity ladder)
  - **expanded baseline metrics on 20 cases**:
    - true-positive rate (TPR): 11/11 = 100% (≥95% §6.2 threshold)
    - false-positive rate (FPR): 0/9 = 0% (≤2% §6.2 threshold)
    - per-correlator TP counts: approval_gap=5, fetch_surface=3,
      identity_persistence=2, educational_demotion=2
  - **16 new tests** added/expanded in
    `tests/test_cross_mode_correlators_phase2.py`:
    - parametrized true-link list extended from 4 to 10 cases (c1-c4
      seed + c8-c11 TPR variants + c17-c18 severity)
    - parametrized true-negative list extended from 3 to 9 cases
      (c5-c7 seed + c13-c16 FPR + c19-c20 severity)
    - new `test_calibration_c12_multi_correlator_fires_both` covers
      independent aggregate emission
    - new `test_calibration_d2_severity_cap_invariant` parametrized
      across 3 severity levels (high+high, low+low, mixed) to lock
      the D2 cap-at-max invariant
    - `test_calibration_baseline_metrics` updated to require ≥11
      true-link cases and ≥9 true-negative cases (was ≥4 / ≥3),
      handles MULTIPLE correlator case via `expected_correlators_fired`,
      uses new `_findings_for_case()` helper that reads explicit
      `expected_dynamic_findings` from case.json when present
  - **case.json schema additions**: optional `expected_dynamic_findings`
    (list of [rule_id, severity] pairs, replaces single-kind mapping
    when needed), optional `expected_aggregate_severity` (string,
    used by D2 boundary tests), optional `expected_correlators_fired`
    (list of correlator names, used by multi-correlator c12 case).
    Backwards compatible — existing 7 seed cases unchanged
  - **calibration corpus README updated** with the 20-case coverage
    matrix and per-correlator TP/TN breakdown

- **M2 Phase 2 — cross-signal correlators + linker + calibration corpus** (item shipped):
  - new modules in `src/agent_audit/cross_mode/`:
    - `signal_record.py` — `SignalRecord` aggregate type per design §2
      (origin_mode, source_kind, canonical_class, severity, confidence,
      repo_root, session_id, scope_key, evidence, needs_llm_verification,
      tags, supporting_signal_ids, correlator, rationale).
      `make_aggregate_record()` constructor centralizes defaults
    - `policy.py` — D2 cap-at-max severity bound (`cap_severity()`),
      D3 priority-only demotion (`demote_priority_via_tag()`),
      confidence lift for joins (`lift_confidence()`)
    - `correlators.py` — 4 named correlators per design §5 with
      grounded rule_ids verified against codebase:
      - `repo_approval_gap_supports_autonomy_risk` (proximity 1):
        tag `has_broad_action_without_approval` + dynamic from
        {C3.autonomy-with-exfil-chain, C3.autonomy-with-persistence,
        C3.autonomy-with-sensitive-sink, AG-04.destructive-without-backup,
        resource.unbounded-loop}
      - `repo_fetch_surface_supports_indirect_injection` (proximity 1):
        tag `has_remote_fetch_instructions` + dynamic
        AI-06.indirect-prompt-injection-vector
      - `repo_identity_surface_supports_persistence_risk` (proximity 2):
        tag `has_identity_rewrite` + dynamic from {AI-04.persistence-write,
        C3.autonomy-with-persistence}, requires session cwd at-or-under
        repo root
      - `repo_educational_context_demotes_runtime_advice` (proximity 1):
        tag `educational_heavy` OR `red_team_heavy` + dynamic
        advice.dangerous-recommendation at severity ≤ medium →
        severity preserved, confidence dropped to "low",
        `context_demoted` tag applied to matched dynamic findings
        per D3
    - `linker.py` — `link_signals(session_id, session_cwd, inventory,
      dynamic_findings) → LinkerOutput`. Honest unlinkable contract:
      returns `unlinkable_reason` for missing inventory or empty
      findings (a normal outcome, not an error). D5 contract
      documented in module docstring: caller is responsible for
      pre-filtering suppressed findings; linker only sees what's
      passed in. Buggy correlator exceptions swallowed per-correlator
      so one bad rule cannot break M2 for a session
    - `calibration_corpus.py` — loader for the synthetic corpus.
      `CalibrationCase` dataclass with cleanup-on-context-exit;
      `_materialize_case()` substitutes `__CASE_PROJECT__` cwd
      placeholder and copies project tree to a tempdir
    - `__init__.py` updated to export the Phase 2 surface
      (SignalRecord, make_aggregate_record, CorrelatorInput,
      CorrelatorResult, LinkerOutput, all_correlators,
      correlator_names, link_signals, findings_to_link_input,
      cap_severity, lift_confidence, demote_priority_via_tag)
  - new `benchmarks/m2-calibration-corpus/` directory with 7 paired
    test cases (4 true-link + 3 true-negative) covering each named
    correlator and the three negative-case patterns (clean baseline,
    tag-but-no-dynamic, dynamic-but-no-tag). Each case carries
    `case.json` with an `m2_expected` ground-truth block, a
    `project/` tree with `.git/HEAD` sentinel for the resolver, and
    a `session.jsonl` with `__CASE_PROJECT__` cwd placeholder. README
    documents layout, coverage matrix, and §6.2 acceptance thresholds
  - **calibration baseline on the 7-case seed**:
    - true-link rate (TPR) = 4/4 = 100%, well above §6.2 ≥95% threshold
    - false-link rate (FPR) = 0/3 = 0%, well within §6.2 ≤2% threshold
    - per-correlator TPR = 1/1 each (each correlator has one TP case
      and at least one TN case in the seed)
    - the 7-case seed is below the 20-pair target in design §6.1;
      expansion to 20+ planned before v0.18 release. The seed exists
      to lock the implementation behavior to known ground truth and
      catch regressions
  - `test_calibration_baseline_metrics` test assertion locks
    TPR ≥ 95% and FPR ≤ 2% as a regression guard. Future correlator
    or rule_id changes that drift these metrics will fail this test
  - **53 new tests** in `tests/test_cross_mode_correlators_phase2.py`:
    - 6 tests for `cap_severity` (max-of, low+low, high+high, unknown
      label, empty input, case insensitivity)
    - 3 tests for `lift_confidence` (two-component, single-component
      fallback, more-than-two cap)
    - 3 tests for `make_aggregate_record` (origin_mode, unique IDs,
      supporting_signal_ids preservation)
    - 6 tests for §5.1 approval_gap correlator (fires, silent without
      tag, silent without dynamic, severity capped, picks up
      destructive + unbounded-loop)
    - 3 tests for §5.2 fetch_surface correlator
    - 4 tests for §5.3 identity_persistence correlator (proximity 2:
      cwd under repo passes, cwd outside fails, tag missing fails,
      cwd None fails)
    - 6 tests for §5.4 educational_demotion (D3 severity preserved,
      context_demoted tag applied, skips high/critical, fires for
      either educational_heavy or red_team_heavy)
    - 7 tests for linker orchestration (unlinkable when no inventory,
      unlinkable when no findings, empty output when nothing fires,
      session_id preserved, multiple correlators run independently,
      buggy correlator exception swallowed, D5 contract documented)
    - 3 tests for `findings_to_link_input` adapter (dicts, objects
      with `.severity.value`, skips empty rule_id)
    - 2 tests for registry sanity (correlator_names returns all 4,
      all_correlators returns callables)
    - 10 calibration corpus tests: 1 corpus-loads, 1 inventory-matches-
      expected, 4 parametrized true-link cases, 3 parametrized
      true-negative cases, 1 baseline-metrics assertion
  - **what is NOT in Phase 2**: the `cross-mode` CLI subcommand (per
    D4 — separate subcommand, not auto-invoke; ships in a follow-up
    commit), mixed-evidence clustering (Phase 3), verifier prompt
    integration (Phase 4)
  - **Phase 2 risk gate satisfied**: 0 regressions, all 4 validators
    green, calibration baseline meets §6.2 thresholds. Full test count
    after Phase 2: 638 passing, 1 skipped

- **M2 Phase 1 — shared inventory + session-to-repo resolver** (item shipped):
  - new package `src/agent_audit/cross_mode/` with two Phase 1
    modules:
    - `inventory.py` — `build_repo_signal_inventory(repo_root)` walks
      a repo and produces a `RepoSignalInventory` dataclass with 9
      structural tags (`has_skills`, `has_mcp_manifests`,
      `has_plugin_manifests`, `has_instruction_files`,
      `has_remote_fetch_instructions`,
      `has_broad_action_without_approval`, `has_identity_rewrite`,
      `educational_heavy`, `red_team_heavy`) and 4 counts. Tags are
      derived from file presence + body-pattern matching against
      instruction-shaped files (SKILL.md, AGENTS.md, CLAUDE.md, .md
      files in `.claude/.cursor/.codex/`)
    - `proximity.py` — `resolve_session_repo(cwd)` walks up from a
      session's recorded `cwd` looking for repo markers (`.git`,
      `.claude/`, `.cursor/`, `.codex/`, `AGENTS.md`, `CLAUDE.md`,
      `pyproject.toml`, `package.json`, etc). Stops at `$HOME`
      boundary; returns None for missing/empty cwd, non-existent
      paths, and repos without any marker (honest unlinkable
      contract per design draft §6.3)
  - **D5 compliance**: structural inventory tags survive user
    suppressions because they describe **structural facts** about the
    repo (this repo has SKILL.md files, this repo has MCP manifests),
    not findings. Tags are computed without consulting
    `agent-audit.yaml` suppressions. Phase 2's finding-level join
    layer will respect suppressions separately
  - **caching**: process-local `_CACHE` keyed on
    `(repo_root, mtime_fingerprint)`. Fingerprint is SHA-1 over
    sorted (path, mtime) pairs of all classified files. Adding,
    removing, or modifying a classified file invalidates. Test
    coverage includes mtime bump invalidation
  - **vendor directory skip**: `node_modules`, `dist`, `build`,
    `__pycache__`, `.venv`, `target`, `out` are pruned from the
    walk to avoid scanning third-party SKILL.md files. Verified by
    test
  - **wire-up into `scanner.scan`**: `ScanResult` gained a new
    `repo_inventories: Dict[str, RepoSignalInventory]` field keyed
    by `session_id`. Populated silently during scan; not yet
    rendered anywhere (Phase 1 invisibility contract). Type-erased
    to `Dict[str, object]` to avoid an import cycle. Failures during
    inventory build are swallowed — must not break the forensic
    scan path
  - **35 new tests** in `tests/test_cross_mode_inventory_phase1.py`:
    - resolver: 11 tests (deep subdir, agent marker without git,
      AGENTS.md at root, build marker last-resort, inner-over-outer
      preference, file→parent fallback, None outcomes for empty
      cwd / nonexistent path / no markers, $HOME stop boundary)
    - inventory discovery: 7 tests (empty repo non-None, skills,
      MCP manifests, instruction files, vendor skip, plugin
      manifests)
    - body-pattern derivation: 6 tests (remote fetch, curl|sh,
      broad action, identity rewrite, FP guard on benign content,
      educational/red-team heavy)
    - caching: 4 tests (same instance return, new file invalidates,
      mtime change invalidates, clear_cache forces rebuild)
    - serialization: 3 tests (to_dict shape, active_tags subset,
      empty-repo active_tags)
    - scanner integration: 2 tests (ScanResult has field, field
      doesn't leak into findings)
  - **Phase 1 risk gate satisfied**: existing scan output unchanged,
    0 regressions across the 550-test v0.17 baseline. Full test
    count after Phase 1: 585 passing, 1 skipped
  - **what is NOT yet implemented**: cross-signal correlators (Phase 2),
    the four named correlators in design §5, mixed-evidence clustering
    (Phase 3), verifier prompt enrichment (Phase 4). The `cross-mode`
    CLI subcommand also waits for Phase 2 — there's no user-facing
    surface in Phase 1

## 0.17.0 (released)

Rules Expansion Roadmap track — see `docs/rules-expansion-roadmap.md`
for the full plan.

- **M2 — cross-mode signal flow** (design draft + decisions, no code):
  - new design document `docs/m2-cross-mode-design-draft.md`,
    **reconciled across two input drafts**: an internal identity-first
    draft plus an external unified-static-dynamic draft. The
    unified-inventory architecture is the strict superset (it covers
    repo-context-tag-only signals where no static finding fired), so
    it forms the spine; the identity-first material contributes
    rigor on the join layer where findings DO meet
  - **D1-D5 settled** in companion memo `docs/m2-d1-d5-decisions.md`:
    - **D1**: hash-only identity at v1; name/path fallback deferred
      pending calibration data. M2 derives most of its value from
      repo tags + proximity + correlators rather than from weak
      identity matching, so conservative joins suffice for v1
    - **D2**: strict cap-at-max severity. Cross-mode support raises
      priority (review queue, verifier queue, issue rank) — never
      severity. Mental model: severity = maximum direct evidence;
      priority = severity plus corroboration
    - **D3**: educational-context demotes priority only, never
      severity. Avoids introducing a second severity-rewrite policy
      on top of the existing scan-project demotion
    - **D4**: separate `cross-mode` subcommand over saved outputs.
      No auto-invoke at v1. Explicit execution boundary aids
      debugging and makes rollout reversible
    - **D5**: two-layer model for project-config interaction.
      Finding-to-finding joins run AFTER suppressions; suppressed
      findings do NOT participate as supporting components.
      Structural inventory tags (`has_skills`, `has_mcp_manifests`,
      etc.) survive suppressions because they describe structural
      facts about the repo, not findings. Aggregate records may cite
      structural tags but NEVER cite a suppressed finding ID
  - **architecture**: unified `SignalRecord` layer between scan
    execution and reporting. Both modes emit records with `origin_mode`
    (static/dynamic/probe/aggregate); cross-signal correlators
    consume them; clustering and verifier prompts read from them
  - **proximity ladder** (independent from identity):
    `repo_present` / `same_subtree` / `named_artifact_touched`.
    Each correlator declares required tier
  - **four named correlators**: approval-gap-supports-autonomy,
    fetch-surface-supports-injection, identity-surface-supports-persistence,
    and educational-context-demotes-advice (the only demotion
    correlator — priority only, severity preserved per D3)
  - **four-phase implementation plan**: shared inventory →
    correlators → mixed clustering → verifier integration. Phases 1-2
    fit ~3 weeks; phases 3-4 in v0.19+
  - **calibration plan**: ≥95% true-link / ≤2% false-link on synthetic
    + corpus_lab cross-pairing. ≥80% per-correlator TPR / ≤5% FPR on
    benign repos. Below thresholds → experimental mode or defer
  - source draft preserved at `docs/m2-source-unified-static-dynamic-design.md`
    for traceability; appendix in the main draft tracks which
    sections came from where
  - **no code shipped** in v0.17. Implementation cleared for v0.18 —
    calibration corpus assembly is the only remaining gate before
    Phase 1 begins

- **D2 / D3 — AgentDyn + WASP injection benchmark adapters** (items shipped):
  - new module `src/agent_audit/injection_benchmarks.py` with two
    loaders (`load_agentdyn_cases`, `load_wasp_cases`) and a unified
    runner (`run_benchmark`). Both corpora live in user-cloned local
    checkouts; we do not bundle either
  - **AgentDyn loader**: walks `src/agentdojo/default_suites/*/*/injection_tasks.py`
    via `ast.parse`, extracts `GOAL = "..."` class attributes from
    `Injection*` classes, substitutes class-level constants like
    `_RECIPIENT = "x@y.com"` into the GOAL text. AST helpers handle
    plain strings, f-strings (placeholders preserved as `{name}`),
    string concatenation, and annotated assignments. Skips files with
    syntax errors gracefully so a single bad upstream file doesn't
    take down the whole walk
  - **WASP loader**: reads `webarena_prompt_injections/configs/experiment_config.raw.json`,
    substitutes `{placeholder}` parameters from the per-entry
    `parameters` block into each `instruction` string, tags cases
    with `environment` (gitlab/reddit/etc) and `exfil` metadata. Skips
    empty-instruction entries, returns `[]` on missing/malformed config
  - **runner**: `run_benchmark` walks every loaded rule pack pattern
    against each case's text (honoring `exclude_patterns` for FP
    suppression — same semantics as production scans), produces a
    `BenchmarkReport` with per-suite recall, per-rule contribution
    counts, undetected sample, and a `to_dict()` for JSON output
  - new CLI subcommand `agent-audit injection-benchmark` with
    `--agentdyn PATH`, `--wasp PATH`, `-o OUTPUT.json`,
    `--show-undetected`. License caveats explicit in help text:
    AgentDyn is MIT, WASP is CC-BY-NC 4.0 (cannot redistribute, must
    clone locally)
  - **why measure recall only**: precision needs a paired benign
    corpus, which lives separately. The benchmark intentionally
    measures one side. High recall on adversarial corpus paired with
    known FP rate on benign content (per A2/C1 calibration) is the
    actionable signal — feeds directly into M3 evaluator gating
    decisions
  - **why not pip-install upstream frameworks**: AgentDyn pulls
    playwright + LLM SDKs + ~60 deps; WASP pulls selenium + webarena.
    None of that matters for static prompt-string measurement. AST
    walk + JSON read over local clones is leaner and license-friendlier
  - **empirical baseline at v0.17.0** (against current upstream
    masters):
    - AgentDyn: 82 cases harvested, recall 93.9% (77/82). Top rule:
      `nova.prompt-injection.policy-puppetry-universal-bypass` on 53
      cases
    - WASP: 21 cases harvested, recall 100% (21/21). Top rule:
      `nova.prompt-injection.job-recruitment-variation-rule` on 14
      cases
    - Note: top-firing NOVA rules on these adversarial corpora are
      the same rules that calibration showed as FP-prone on benign
      content. High recall + known FP rate = the M3 evaluator's
      target population
  - new doc `docs/benchmark-corpus-howto.md` covering setup, license
    caveats, what the adapters do/don't do, baseline numbers, and
    failure modes (missing repo / layout changes / malformed config
    all return `[]` gracefully rather than raising)
  - 36 new tests in `tests/test_injection_benchmarks_d2_d3.py` covering
    AST helpers (plain string, f-string, attribute access,
    concatenation, non-string), AgentDyn loader (synthetic 3-class
    corpus, non-injection class skip, class constant resolution,
    metadata, missing repo, fallback layout, syntax-error tolerance),
    WASP loader (synthetic 3-case config, parameter substitution,
    metadata recording, empty-instruction skip, missing repo, missing
    config file, malformed JSON), runner mechanics (pattern matching,
    exclude gate, preview truncation, per-rule deduplication), and
    end-to-end report shape (empty corpus zero-recall, perfect recall,
    partial recall, per-rule hit counts, JSON shape, undetected sample
    cap, real-rules smoke). Tests use synthetic fixtures, do not
    require either corpus to be cloned

- **B4 — AVID (AI Vulnerability Database) cross-link** (item shipped):
  - new module `src/agent_audit/knowledge/avid_mapping.py` carrying
    the canonical 48-entry SEP enum (verbatim from upstream avidtools)
    plus a 29-entry `(source_tool, category) → (SEP IDs)` table
    covering every category produced by the live rule packs
  - loader enrichment populates `references["avid"]` automatically for
    every rule whose category has a known mapping. Same flow as MCP
    and ASI enrichment, independent from those: AVID groups by failure
    mechanism (Software Vulnerability vs Information Leak vs Model
    Bypass) whereas OWASP MCP/ASI group by agent-specific risk class
  - new tool `tools/avid_validate.py` and CLI `agent-audit avid-validate`
    with `--strict`, `--include-missing`, `--json`, `--quiet` flags.
    Catches three drift classes: UNKNOWN SEP IDs, NAME_MISMATCH against
    upstream titles, and MISSING references. Same shape as
    atlas-validate, owasp-mcp-validate, owasp-agentic-validate
  - CI strict gate added in `.github/workflows/ci.yml` — fourth
    reference validator. CI now catches drift in four taxonomies:
    MITRE ATLAS, OWASP MCP Top 10, OWASP Agentic Top 10, AVID SEP
  - **coverage**: 100% across all 702 loaded rules. 1372 total avid:
    references spanning 12 distinct SEP IDs (S0100 Software
    Vulnerability, S0200 Supply Chain, S0202 Software Compromise,
    S0300 Over-permissive API, S0301 Information Leak, S0400 Model
    Bypass, S0403 Adversarial Example, S0500 Exfiltration, S0502
    Model theft, S0600 Data Poisoning, S0601 Ingest Poisoning, P0300
    Privacy)
  - **explicitly out of scope**: per-record AVID-YYYY-V/R IDs (the 2026
    GPAI rebuild made record IDs less stable across migrations);
    Lifecycle view (L01-L06 — developer-side dimension that doesn't
    slice cleanly along rule-pack lines); vendored snapshot file (SEP
    is small enough to keep inline; weekly DB releases would force
    constant snapshot churn for little benefit)
  - 30 new tests in `tests/test_avid_b4.py` covering mapping integrity,
    SEP ID format, label canonical form, lookup helpers, loader
    enrichment, validator drift detection, and specific pack→SEP joins
    (so future changes to mapping decisions surface in test failures)

- **N1 — tool-pinning / rug-pull state-tracking detector** (item shipped):
  - new module `src/agent_audit/tool_pinning.py` — first stateful native
    detector in the codebase. Records SHA-256 hash of every MCP tool
    description on first scan, emits findings on subsequent scans when
    those hashes change. Inspired by Invariant Labs `mcp-scan` rug-pull
    detection
  - **storage**: per-project baselines under
    `~/.agent-audit/tool-pinning/<sha1(abspath)>.json` with
    `schema_version`, `tools` map, `first_seen` / `last_seen` /
    `scan_count` metadata. Atomic write via .tmp + rename.
    `AGENT_AUDIT_STATE_DIR` env override for testability and CI
  - **three finding kinds**:
    - `N1.tool-pinning.description-changed` — HIGH severity, the actual
      rug-pull. Carries before-and-after preview in evidence and a hash
      prefix so the change is auditable. References include
      `ASAMM:AD-02`, `OWASP MCP08`, and a research pointer to mcp-scan
    - `N1.tool-pinning.tool-added` — LOW severity, informational. New
      tool appeared since last scan
    - `N1.tool-pinning.tool-removed` — LOW severity, informational.
      Tool disappeared since last scan
  - **identity model**: `(manifest_relpath, server_name, tool_name)`.
    Two different manifests with the same `(server, tool)` produce
    different keys — no conflation. Description content is NOT in the
    identity, so description changes show up as drift, not as
    add+remove pairs
  - **normalization before hash**: NFC Unicode + whitespace-run
    collapse. Zero-width characters (ZWSP, ZWNJ) survive intentionally
    — a rug-pull that smuggles invisible characters into a description
    IS the attack class we want to detect, so the hash must be
    sensitive to them. Whitespace reformatting alone (different
    indentation, extra spaces) does NOT trigger drift, because that's a
    common authoring change with no semantic effect
  - **two-flag CLI design**: `scan-project` gained
    `--track-tool-pinning` (off by default, mutating state on ad-hoc
    scans is a footgun) and `--update-pinning-baseline` (only
    meaningful with the above; without it, drift fires on every
    subsequent scan — important for CI semantics where the same
    rug-pull should keep firing until explicitly accepted)
  - **fingerprint resolves symlinks**: scans through different paths to
    the same project (e.g. `/var/tmp/repo` vs `/private/var/tmp/repo`
    on macOS) share state. No spurious "first scan" resets
  - **CLI bonus**: `--tool` choice list expanded to include `gitleaks`
    and `nova` (was stale from before A3/A2)
  - 41 new tests in `tests/test_tool_pinning_n1.py` covering fingerprint
    determinism + symlink resolution, normalization preserving ZWSP and
    collapsing whitespace, manifest discovery for all four common
    locations (.claude/, .cursor/, .vscode/, claude_desktop_config.json),
    inline-tools and server-level-description extraction shapes,
    malformed JSON handling, baseline I/O including atomic write and
    corruption recovery, all three finding kinds, and the persistence
    semantics of `--update-pinning-baseline` vs the CI-friendly default
  - **explicitly out of scope**: schema-shape rug-pulls (input args,
    output type changes — separate detector class); server-side
    description changes when the project doesn't ship the manifest
    (requires runtime probing, not file inspection); first-scan
    baseline poisoning detection (mitigation is to pair N1 with the
    static tool-description rule packs, both run in the same
    `scan-project` invocation)

- **M3 — NOVA semantics + llm evaluator** (item shipped):
  - new module `src/agent_audit/nova_evaluator.py` — post-hoc evaluator
    for the NOVA `semantics:` and `llm:` gates that A2/C1 had to skip.
    The evaluator runs after `scan-project` and adjusts NOVA finding
    severity in place based on which gates pass
  - new CLI subcommand `agent-audit nova-evaluate` — takes a
    `project-findings.json` and runs the gates. Flags
    `--no-llm`/`--no-semantics` allow running with one gate when the
    other dependency is unavailable. `--dry-run` prints verdicts
    without mutating
  - **semantics gate**: cosine similarity between the matched snippet
    and each upstream prose pattern. Uses sentence-transformers
    (`all-MiniLM-L6-v2`, ~80MB). Pass = max similarity ≥ strictest
    declared threshold across patterns
  - **llm gate**: yes/no question to a `VerifierBackend` (Claude CLI,
    Codex CLI, Anthropic API, OpenAI-compatible). Pass = ALL llm
    checks return yes. Conservative AND because we don't have the
    upstream condition structure available at evaluation time
  - **severity decision matrix**: both gates pass → upstream severity;
    both fail → INFO (suppressed); disagree → demote one notch (trust
    failing gate); only one gate available + passes → partial lift;
    only one gate fails → demote; neither gate available → no change
    (fail-open, matches v0.17 baseline)
  - **loader extension**: `RulePackRule` gained three optional fields
    populated only for NOVA rules: `upstream_semantics_patterns`,
    `upstream_llm_checks`, `upstream_severity` (the pre-flooring
    severity from .nov meta block). The A2/C1 importer was updated to
    write `upstream_severity` to YAML; older imports without it default
    to MEDIUM as a conservative cap
  - **calibration outcome**: synthetic SKILL.md that produced 5
    LOW-severity NOVA findings under A2/C1 now demotes 4 of those to
    INFO under semantics-only evaluation (no LLM key needed) — matched
    snippets are semantically distant from upstream prose about
    phishing themes, policy puppetry, APT TTPs, and PII disclosure
  - 36 new tests in `tests/test_nova_evaluator_m3.py` covering every
    cell of the decision matrix, fail-open paths when dependencies are
    missing, mock LLM backend with yes/no/error responses, and
    end-to-end smoke on the real NOVA pack. Tests do not require
    sentence-transformers — the model is mocked or treated as
    unavailable in unit tests
  - **explicitly out of scope**: network embedding APIs (OpenAI,
    Cohere); per-rule threshold tuning; auto-running M3 inside
    `scan-project` (today users invoke `nova-evaluate` separately).

- **A2/C1 — NOVA rule pack + hybrid format adapter** (item shipped):
  - new fifth rule pack at
    `src/agent_audit/knowledge/rule_packs/external/nova/` —
    **46 rules** imported from
    [Nova-Hunting/nova-rules](https://github.com/Nova-Hunting/nova-rules)
    (MIT, c) 2025 Thomas Roccia). Total static-applicable rules:
    527 → **573**. Pack count 4 → **5**
  - new build-time tool `tools/nova_import.py` — parses NOVA's
    YARA-inspired DSL (.nov files) into our YAML format. Hand-rolled
    parser handles the three sections (`keywords`, `semantics`,
    `llm`) and the `condition:` boolean expression
  - **lossy-by-design import**: NOVA's full evaluator requires
    embedding model (semantics) + LLM endpoint (llm); we have neither
    yet. Importer ingests **keywords only**, preserves
    `semantics`/`llm` as upstream metadata fields
    (`upstream_semantics_patterns`, `upstream_llm_checks`,
    `upstream_condition_raw`, `upstream_condition_mapping_note`) for
    a future M3 evaluator
  - `condition:` expression mapping: `any of keywords.*` → `match_mode: any`,
    `N of keywords.*` where N == total → `all`, otherwise `any` with a note;
    mixed conditions involving semantics/llm drop those gates and keep
    the keyword conjunct only. The condition shape that won't fit our
    matcher is documented per-rule via `upstream_condition_mapping_note`
  - 4 NOVA rules with no keywords section (semantics/llm only) are
    skipped on import — there's nothing for our regex matcher to enforce
  - **all NOVA rules imported at LOW severity**, regardless of upstream
    declared severity. Calibration on a benign SKILL.md showed multi-word
    keyword conjunctions firing on innocuous documentation (the
    "messaging-scripting" rule fired on the words "code", "script",
    "program" appearing anywhere; "policy-puppetry-universal-bypass"
    fired on `<interaction-config>`-shaped HTML). Keyword-only signal
    is too weak to honor upstream severity. Lift selectively when M3
    NOVA evaluator lands. Documented per-rule via
    `upstream_severity_demotion_note`
  - **NOVA rules ship with static surfaces only** (no `session_*` audit
    surfaces) — same noise concern applies in forensic mode. M3 will
    enable session surfaces alongside lifting severity
  - new `_NOVA_CATEGORY_MAP` resolves NOVA's path-style categories
    (`prompt_manipulation/jailbreak`, `suspicious_patterns/encoding_obfuscation`,
    etc.) to our internal categories (`prompt-injection`,
    `context-exfiltration`). Unknown categories fall back to
    `prompt-injection` so MCP/ASI mapping still flows
  - `_CATEGORY_TO_MCP` and `_CATEGORY_TO_ASI` extended with
    `nova.prompt-injection` and `nova.context-exfiltration` keys.
    Coverage remains 100% across all 573 rules
  - new GitHub Actions job `nova` in
    `.github/workflows/refresh-vendored-data.yml` — weekly fetch,
    re-import, run A2/C1 regression tests, run all 3 reference
    validators, open PR if upstream changed. PR body explains the
    keyword-only import policy
  - 35 new tests in `tests/test_nova_a2_c1.py` covering rule splitting,
    full file parsing, condition mapping (all five condition shapes
    seen in the upstream corpus), severity-flooring, static-surface-only
    constraint, end-to-end import, and the 5-pack count assertion

- **M3 — NOVA evaluator (semantics + llm)** added to roadmap as
  follow-up item. Lifts keyword-only restriction; restores upstream
  severity levels; enables session surfaces.

## 0.16.0 (released)

Rules Expansion Roadmap track — see `docs/rules-expansion-roadmap.md`
for the full plan.

- **A3 — Gitleaks rule pack** (item shipped, completes v0.16.0):
  - new fourth rule pack at
    `src/agent_audit/knowledge/rule_packs/external/gitleaks/` —
    **217 secret-detection rules** imported from
    [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks)
    (MIT, c) 2019 Zachary Rice). Total static-applicable rules:
    310 → **527** (a 70% increase from this single source)
  - new build-time tool `tools/gitleaks_import.py` — TOML→YAML
    normalizer that converts Gitleaks's single-file config into our
    per-rule YAML format. Idempotent; output committed to repo so
    runtime needs no Gitleaks dependency
  - **regex compatibility layer**: Gitleaks's regexes target Go's RE2
    engine; Python `re` differs in a few details. The importer's
    `_normalize_regex()` hoists interior `(?i)` flags to the front
    (Python 3.11+ deprecates them mid-pattern) and skips genuinely
    incompatible patterns rather than silently breaking. 217/222 rules
    survive normalization (97.7%); 4 require manual upstream attention,
    1 has no regex
  - **baseline FP-prevention**: every imported rule carries a shared
    `exclude_patterns` block with known canonical example tokens
    (`AKIAIOSFODNN7EXAMPLE`, `ghp_xxxxxxxxxxxxxxxxxxxx`,
    `<your_api_key_here>`, `YOUR_OPENAI_API_KEY`, RSA test fixtures,
    etc.). Calibration on benign skill SKILL.md showed 0 Gitleaks
    findings on AWS/GitHub/OpenAI canonical examples; the same skill
    fired 3 Aguara credential-leak findings, suggesting Aguara's own
    excludes are narrower than ours
  - all 217 Gitleaks rules categorized as `hardcoded_secrets`, mapped
    to `ASAMM:AG-03` (credential exposure), `OWASP MCP01` (Token
    Mismanagement), `OWASP ASI03` (Identity & Privilege Abuse). Default
    severity HIGH
  - upstream `entropy` and `path` fields preserved in YAML as
    `upstream_entropy_threshold` and `upstream_path_regex` for future
    enforcement (current matcher does not gate by Shannon entropy)
  - `cisco-promptguard.hardcoded_secrets` source-tool key added
    alongside the legacy `cisco-pg.*` form (the loader emits the former
    as `source_tool`; both keys map to the same MCP/ASI IDs)
  - new GitHub Actions job `gitleaks` in
    `.github/workflows/refresh-vendored-data.yml` — weekly fetch,
    re-import, run A3 regression tests, run all 3 reference validators,
    open PR if upstream changed
  - 31 new tests in `tests/test_gitleaks_a3.py` covering
    `_normalize_regex` compatibility paths, slug stability,
    end-to-end import on a synthetic TOML, baseline-exclude
    enforcement on AWS/placeholder canonical examples, and TP-sanity
    on a realistic AWS-shaped key
  - regex compile-time `FutureWarning` from POSIX character classes
    like `[[:alnum:]]` (used by 1 Gitleaks rule) is now suppressed in
    `rule_pack_loader._compile_patterns()` — the regex still works,
    Python just complains. Cleaner stderr.

- **M1 — unified rule execution: close the forensic/static diagonal**
  (item shipped):
  - new module `src/agent_audit/session_rule_executor.py` adapts
    rule-pack rules (310 total) for forensic mode. Rules with at least
    one `session_*` audit_surface (`session_user_input`,
    `session_agent_output`, `session_tool_call`, `session_tool_args`,
    `session_tool_output`, `session_tool_response`,
    `session_event_stream`) now run against `Session.events[]` in
    addition to file content
  - `scanner.py` calls `run_session_rule_packs()` after the existing
    `run_session_rules()`, so findings come from both native detectors
    AND rule-pack rules
  - **78 rule-pack rules** that previously had zero forensic effect
    (they declared session surfaces but were never executed) are now
    live. The pre-existing `_compile_patterns(static_only=True)`
    machinery already kept these patterns out of static scans;
    M1 closes the mirror gap on the forensic side
  - per-event de-duplication: rules declaring multiple overlapping
    surfaces (e.g. `session_tool_output` + `session_event_stream`)
    produce one finding per event, not one per surface
  - per-rule error isolation: a buggy rule emits a low-severity error
    finding instead of aborting the session scan
  - findings carry `mode:forensic-from-rule-pack` reference for
    downstream reporting layers to distinguish from native-detector
    findings
  - 29 new tests in `tests/test_unified_rule_execution.py` covering
    field extraction, adapter behavior, deduplication, error isolation,
    and a regression guard that fails if a future rule pack adds a
    `session_*` surface this executor doesn't handle
  - **explicitly out of scope**: porting native detectors to static
    surfaces (different work per detector — they consume `Session` /
    `agent_home`, not file paths), and cross-mode signal flow (M2,
    deferred — needs an identity model for joining static findings to
    forensic events)

- **A1 — Aguara rule-pack upgrade 37 → 189 rules** (item shipped):
  - vendored upstream Aguara at SHA `d8797926` (HEAD as of refresh) under
    `src/agent_audit/knowledge/rule_packs/external/aguara/`
  - **189 rules across 13 categories** (was 37 across 3): adds
    command-execution (16), credential-leak (22), exfiltration (16),
    indirect-injection (10), mcp-attack (16), mcp-config (13),
    prompt-injection (18), supply-chain (21), supply-chain-exfil (10),
    unicode-attack (10) on top of the existing external-download,
    ssrf-cloud, third-party-content
  - new tool `tools/aguara_import.py` — idempotent converter from
    upstream multi-doc YAML to our per-rule format with attribution
    and ASAMM mapping. Build-time only; output committed to repo
  - extended `_CATEGORY_TO_MCP` and `_CATEGORY_TO_ASI` mapping tables
    for all 10 new categories — coverage is now **100%** of all 310
    static-applicable rules (was 78% before A1) for both OWASP MCP
    and OWASP Agentic taxonomies
  - fixed pre-existing source-tool key mismatch: mappings used
    `cisco-pg.*` keys but loader assigns `source_tool=cisco-promptguard`.
    Both forms now mapped explicitly
  - **architectural fix — `targets` field enforcement**: rules
    declaring upstream `targets: ['*.pth']` (or any other extension
    glob) now only match files matching the glob. Without this guard
    Python `.pth`-targeted rules were firing on Markdown documentation
    that happened to contain `import` or `from`. Implementation:
    `_file_matches_targets()` in `project_scanner.py` plus loader
    promotion of `targets:` to `RulePackRule.file_types`
  - new GitHub Actions job in `refresh-vendored-data.yml` that
    weekly fetches upstream Aguara, re-imports, runs the A1 regression
    tests, and opens a PR if upstream has changed
  - 17 new tests in `tests/test_aguara_a1.py` — covers `_file_matches_targets`,
    end-to-end no-FP-on-benign-markdown, and category coverage
  - **Total rules:** 167 → **310** (static-applicable). Pack
    breakdown: aguara=180, atr=104, cisco-promptguard=26.

- **B2 — OWASP Agentic AI Top 10 systematic mapping** (item shipped):
  - vendored canonical reference index `owasp_agentic_top10.yaml` (10
    ASI categories, December 2025 release v1.0.0) under
    `src/agent_audit/data/owasp_agentic/` — synthesized from the OWASP
    upstream PDF since OWASP doesn't publish a structured machine-readable
    export. Attribution preserved (CC BY-SA 4.0)
  - new module `knowledge/owasp_agentic_mapping.py` mapping rule-pack
    `(tool, category)` and native ASAMM rule-id prefixes to ASI01–ASI10
  - rule-pack loader now also auto-enriches `references.owasp_agentic`
    at load time; **131 of 167** static-applicable rules now carry derived
    ASI refs (alongside existing `owasp_mcp` enrichment)
  - new validator `tools/owasp_agentic_validate.py` with the same shape
    as `owasp-mcp-validate` and `atlas-validate`
  - new CLI subcommand `agent-audit owasp-agentic-validate`
  - 25 new tests in `tests/test_owasp_agentic.py`
  - **68 ASI rewrites added** to `rule_pack_overrides.yaml` resolving
    the entire draft → 1.0.0 taxonomy drift (e.g. `Agent Behaviour Hijack`
    → `Agent Goal Hijack`, `Memory & Context Poisoning` → `Memory and
    Context Poisoning`, six different titles previously cited under ASI03
    all normalized to `Identity and Privilege Abuse`). All three validators
    now pass `--strict` mode against the real repo
  - one native detector reference fix: `no_approval_model.py`'s ASI
    references updated from `ASI03 + ASI06` (semantically inaccurate
    after taxonomy finalization) to `ASI10 + ASI03` (matches the
    mapping table for `asamm.AD-02`)

- **B1 — OWASP MCP Top 10 mapping** (item shipped):
  - vendored OWASP MCP Top 10 markdown + LICENSE (CC BY-SA 4.0) under
    `src/agent_audit/data/owasp_mcp/`
  - generated machine-readable index `owasp_mcp_top10.yaml` (10 categories)
  - new module `knowledge/owasp_mcp_mapping.py` mapping rule-pack
    `(tool, category)` and native ASAMM rule-id prefixes to MCP01–MCP10
  - rule-pack loader auto-enriches `references.owasp_mcp` at load time;
    **131 of 167** static-applicable rules now carry derived OWASP MCP refs
  - new validator `tools/owasp_mcp_validate.py` with the same shape as
    `atlas-validate`: unknown ID / name mismatch / missing-backfill modes,
    lenient/strict, JSON output
  - new CLI subcommand `agent-audit owasp-mcp-validate` with `--strict`,
    `--include-missing`, `--json`, `--quiet` flags
  - 29 new tests in `tests/test_owasp_mcp.py`
  - `finding_dedup.owasp_mcp_for_finding(rule_id)` helper for
    canonical-class consumers

- **References-rewrite mechanism** (side-quest from B3):
  - extended `rule_pack_overrides.yaml` with a new `references_rewrite`
    section for global text-replacement of upstream taxonomy strings
  - applied at rule load time; `atlas-validate` and `owasp-mcp-validate`
    consume the same rewrites so CI gates measure runtime state, not
    raw YAML text
  - shipped 12 ATLAS name-drift fixes (e.g. `ML Supply Chain Compromise`
    → `AI Supply Chain Compromise`, `LLM Plugin Compromise` → `AI Agent
    Tool Invocation`) — all 12 name-drift cases from the v0.16 B3 run
    now resolved
  - `agent-audit atlas-validate --strict` now exits 0 against the real
    repo
  - 13 new tests in `tests/test_references_rewrite.py`

- **CI infrastructure** (extends earlier v0.16 work):
  - `.github/workflows/ci.yml` now runs both `atlas-validate --strict`
    and `owasp-mcp-validate --strict` on every PR
  - `.github/workflows/refresh-vendored-data.yml` adds an `owasp-mcp`
    job parallel to the existing `atlas` job; both refresh weekly

- **B3 — MITRE ATLAS reference validator** (item shipped):
  - vendored ATLAS data snapshot at `src/agent_audit/data/atlas/ATLAS.yaml`
    (Apache-2.0, refresh quarterly per documented procedure)
  - new tool `agent_audit.tools.atlas_validate` walks every rule pack YAML
    plus native detector source and validates `mitre_atlas:*` references
    against the snapshot
  - catches three drift classes: unknown ID, deprecated/revoked technique,
    and name-mismatch (default lenient on names; `--strict` makes name drift
    a hard error too)
  - new CLI subcommand `agent-audit atlas-validate` with `--strict`,
    `--json`, `--quiet` flags
  - 28 new tests under `tests/test_atlas_validate.py` (228 total tests)
  - first run found 12 name-drift cases on existing rule references
    (ATLAS's AI/ML wording sweep: `ML Supply Chain` → `AI Supply Chain`,
    `LLM Plugin Compromise` → `AI Agent Tool Invocation`, etc.). All
    21 cited technique IDs were valid and non-deprecated; the 12 name
    drifts were resolved in the same release via the new
    `references_rewrite` mechanism (see entry above).

## 0.15.0

- aligned package, module, and CLI versioning for a release build
- added canonical verified-first report bundle outputs:
  - `README.md`
  - `manifest.json`
  - `summary.json`
  - `findings-raw.json`
  - `findings-verified.json`
  - `sessions-of-concern.json`
  - `config-findings.json`
  - `local-probes.json`
  - `behavior-findings.json`
- added structured verifier integrity metadata, including `integrity_revisions[]`
- added `scan-project` sidecars:
  - `files-of-concern.json`
  - `report-profiles.json`
  - compatibility alias `sessions-of-concern.json`
- added `corpus-lab` command for large-corpus regression snapshots and gating
- fixed Codex config false positive where unset `approval_mode` was treated as full-auto
- replaced local-machine absolute paths in docs/examples with portable placeholders
- added release-facing project docs:
  - `SECURITY.md`
  - `CONTRIBUTING.md`
- added minimal GitHub Actions CI

## Historical Notes

Detailed pre-`0.15.0` iteration notes were moved out of the README to
[docs/HISTORICAL_CHANGELOG.md](docs/HISTORICAL_CHANGELOG.md).
