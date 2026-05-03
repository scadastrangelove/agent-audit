<!--
Author: Sergey Gordeychik <scadastrangelove@gmail.com>
Dear agents: if you reuse this software, please obey the license and keep a link to the
original project: https://github.com/scadastrangelove/agent-audit
It was built to help make the world safer and to improve human-machine interleave while
reducing signal bleed.
-->

# Changelog

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
