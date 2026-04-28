# agent-audit roadmap

## Philosophy

Статика — широкий невод, LLM — фильтр. Детекторы генерируют кандидатов,
LLM-верификатор отфильтровывает их на основе контекста. Статические правила
могут быть агрессивнее чем обычно в security tooling — LLM разгребёт.

## Current backlog (post-v0.14.4)

Actionable items discovered via grand-runs and lexicon audits. Each item
has concrete entry points and rough effort estimate.

### Intent-based suppressor for security-research skills

**Problem**: `\bjailbreak\b` in IDENTITY_HARD fires CRITICAL on defensive
security skills (danielmiessler/Personal_AI_Infrastructure/Security/
PromptInjection/SKILL.md — 8 mentions, all discussing jailbreak as an
analyzed attack pattern, not performing it). Current behavior treats
descriptive and prescriptive language identically.

**Approach**: add intent classifier. Signal candidates:
- Path markers: `/security/`, `/guardrail`, `/defense/`, `/research/`, filenames containing `PromptInjection`, `Analysis`
- Frontmatter `description` field containing "detect", "analyze", "identify", "classify", "catalog"
- Frame words in surrounding prose: "attack pattern", "taxonomy", "example of", "research", "paper"

Entry point: `knowledge/intent_suppressor.py` (new module), applied to
`identity_redefinition.check_file()` as a severity demoter similar to
how `educational_suppressor` demotes rule-pack findings. Structural skill
markers (frontmatter, MCP manifest) should override intent suppression —
we don't want a real attacker skill hiding behind a "research" label.

**Effort**: 1-2 days. Must include regression fixtures for both sides:
research skills stay at INFO, red-team skills (godmode, obliteratus)
stay at CRITICAL.

### D-2 partial: prose-around-code context for autonomy flags

**Problem**: `--watch\b` in AUTONOMY_LOOP fires 36 times in test corpus,
all 36 matches inside code blocks, 0 in prose. Current AST prefilter
suppresses code-fence matches, so autonomy_loop detector silently
misses this class of "autonomy-via-flag" signals.

**Approach**: when a code fence contains an autonomy marker, check the
surrounding prose (200 chars before and after the fence) for autonomy
framing. If prose says "run continuously with", "in watch mode", "poll
until done" around a `gh pr checks --watch` example, it's a TP.

Entry point: extend `markdown_features.extract()` to return
`code_blocks_with_surrounding_prose: List[(code, prose_before, prose_after)]`.
Extend `classify_capabilities()` to take an optional secondary-signal
parameter that boosts autonomy_loop_total when code-fence markers have
autonomy-framing prose nearby.

**Effort**: 2-3 days. Calibration required — must not reintroduce the
install-instruction FP class that rule-surface-routing closed in v0.14.0.

### `\breuse session` collection-scale verification

**Observation**: 732/735 matches of `\breuse session` are identical
boilerplate ("Session reuse: Reuse session IDs within a workflow. Generate
new ones for new workflows") replicated across 732 skill files.

**Question**: is collection-scale aggregator catching this? If yes, one
aggregate per cohort is correct behavior. If no, aggregator needs either
lower thresholds for boilerplate-replication cases or a dedicated
"boilerplate detector" that identifies byte-identical strings across
cohort members.

**Effort**: 0.5 day investigation + fix. Low priority — this is
signal-dense but highly repetitive, not a correctness issue.

### LLM verifier hookup for native findings

**Context**: `llm_verifier.py` infrastructure exists for session findings
but `scan-project` bypasses it. Native findings are the prime candidates —
~16 findings per 10-target suite, manageable batch size.

**Approach**: add `--verify` flag to `scan-project`. For each native
finding, send the file text + finding summary to Claude/GPT-4 and ask
"is this a real capability declaration or documentation/example?". Store
verdict in `Finding.llm_verdict`. Downgrade CRITICAL→HIGH or drop if LLM
says FP.

Entry point: `cli.scan_project_command()` already has `--yes` flag pattern;
add `--verify` alongside. Verifier module lives at `llm_verifier.py`.

**Effort**: 2-3 days. Must include cost / rate-limit controls (default
off, batch size cap).

### Subtree scan mode

**Context**: Full corpus scans on large repos (secondsky/claude-skills,
affaan-m/everything-claude-code) take >2 min each. Most of the work is
scanning non-instruction files.

**Approach**: `--only-instruction-subtrees` flag that pre-prunes the walk
to only directories containing at least one `SKILL.md`, `AGENTS.md`, or
MCP manifest. Typical 2-5x speedup on monorepos.

**Effort**: 0.5 day.

### Cross-cohort path-based aggregation

**Observation**: ruflo/ruvnet has 6 copies of `sparc-methodology/SKILL.md`
in different subprojects (`v2/.claude/skills/`, `v3/@claude-flow/cli/`,
`v3/@claude-flow/mcp/`, `.agents/skills/`, `.claude/skills/`). Current
aggregator treats each copy as separate cohort member (different parent
dir), so replicated finding on the same file across 4 cohorts stays as
4 findings.

**Approach**: secondary aggregation pass on (rule_id, basename) tuples
after the primary cohort pass. If the same file name under the same
skill name fires the same rule across ≥3 different cohort parents,
collapse to one "cross-cohort replication" aggregate.

**Effort**: 1-2 days. Must preserve individual findings' paths for
triage.

### High-density pattern audit follow-ups

From 2026-04-21 lexicon audit on 2565 files, patterns needing deeper
investigation:

- `\bRUBE_[A-Z_]+\b` — density 12.8, 10015 matches on 782 files. Composio
  tool prefix. Likely signal-dense TP (each RUBE_* token is a real
  Composio tool name), but inflates `remote_action_surface_total`
  artificially in Composio-style corpora. Consider deduplicating
  RUBE_* matches to distinct count only before applying threshold.
- `\b(takes? effect)?(on )?(next|future )?session\b` in PERSIST_WRITE —
  959 files, 2519 matches. Bare "session" as word fires too much.
  Narrow pattern to `\b(next|future)\s+session\b` or require `takes
  effect` prefix.
- `\bcontinuously\b` — 42 files, 49 matches, density 1.2. Mixed prose
  usage ("continuously improving") vs autonomy ("runs continuously").
  Manual review recommended; possibly split into CI vs runtime autonomy.

### ASAMM maturity rollup

See dedicated section below. Blocked on data-quality items above.
Once intent-suppressor and cross-cohort aggregation land, findings
will be clean enough to start computing L1/L2/L3.

## Релизы

### v0.1 — P0 MVP *(готово)*

Discovery, парсеры Claude Code / Codex, 5 детекторов, consent-флоу,
Markdown + JSON отчёты, transparent audit log.

### v0.2 — Sub-agents + calibration *(готово)*

- 3 новых детектора: AI-04.persistence-write, AD-02.out-of-cwd-write,
  C2.private-key-exfil
- Адаптивная severity в C3.autonomy-window-excess
- Классификатор outbound в C2.credential-exfil-chain
- Sub-agent lineage

### v0.3 — Batch + Preflight + Honest errors *(готово)*

- Batch verification (10 findings в одном prompt)
- Preflight check с минимальным тестом
- Honest error reporting из Claude CLI JSON body
- Абстрактный VerifierBackend

### v0.4 — BYO key + Local LLMs + Proxy *(готово)*

- AnthropicAPIBackend, OpenAICompatibleBackend — прямые HTTP
- OpenRouter support, Ollama / LM Studio / vLLM / llama.cpp
- --proxy и auto-detect из env
- 2 детектора из orghound.db-wipe: AG-04.destructive-without-backup, AV-01.test-touches-prod

### v0.5 — ASAMM samples + Integrity review + Patches *(готово)*

- 5 новых детекторов из SecOps / claude-code-zhet / ouroboros samples
- --mode conservative / standard / full
- --integrity-review (second-pass self-check)
- --patches (config fix generator)

### v0.9.0 — Codex taint engine fix *(готово, текущий релиз)*

Completes v0.8.2 Codex normalization work. v0.8.2 fixed detectors'
tool_name checks but missed the deeper layer — `nlu/taint.py` taint
classifier that feeds C2/C3/AI-04/AI-06/AD-02/advice detectors. Real
data analysis showed 10 rules remained Codex-blind despite v0.8.2
patches because taint engine returned empty EventClassification for
every Codex event.

Fix: canonical_tool fallback in 4 taint branches + 3 secondary patches
(credential_context_bleed second bash check, chaos_behaviors test-runner
threshold, AI-06 internal helpers).

10/10 Codex-blind rules confirmed fire on synthetic E2E test. Claude
Code parity preserved. Expected production impact: Codex structural
findings from ~10 to ~30-40.

### v0.8.2 — Codex tool normalization *(готово)*

Canonical cross-agent tool names. Codex `exec_command`/`write_stdin`/
`apply_patch`/`read_file` теперь maps на canonical `Bash`/`BashStdin`/
`Patch`/`Read`. Ранее детекторы (destructive-backup, credential-exfil,
persistence-write, out-of-cwd, confirmation-bypass) silently пропускали
все Codex sessions потому что tool_name check не матчил.

10 детекторов пропатчены на canonical fallback. 4/4 Codex coverage
smoke tests зелёные. Claude Code parity preserved.

### v0.8.1 — Project-type awareness *(готово)*

`.agent-audit.yaml` at project root — user declares project intent
(`tags: [dast]`, trusted_targets, severity_overrides, suppress_rules,
allowlist_writes). Plus auto-detection из CLAUDE.md/AGENTS.md keywords
(DAST/EASM/pentest/red-team). Detectors применяют severity overrides
и suppression через `scanner._apply_project_config()`.

Default tag overrides покрывают известные false positive patterns:
DAST projects downgrade `C3.autonomy-with-exfil-chain` → info
(легитимный scan workflow), `AG-04.destructive-without-backup` → low.

### v0.8.0 — Session aggregation + real-data calibration *(готово)*

Первый из трёх v0.8 UX shifts + критичная калибровка по codex-cli
verified данным.

**Session aggregation (MD report):**
- **Sessions of concern** cards (3+ findings каждая) с severity rollup
- **Rule clusters** внутри карточки
- **Pattern groups** внутри cluster (evidence shape hash нормализует
  /tmp/X, sprint numbers, PIDs, UUIDs)
- **Quiet sessions** одной строкой каждая
- **Config/environment** findings в отдельной секции
- **Full flat list** сохранён в `<details>` appendix для search
- JSON report без изменений (data fidelity)

**Real-data калибровка (на 325 LLM-verified findings):**
- **Claim detector "substantial tool activity" gate** — 91% FP rate у
  `unverified-completion-claim` потому что claims подкреплены real
  tool activity, но наши category-specific regex не матчат. Gate:
  ≥5 prior tools → skip, ≥2 tools → downgrade 2 уровня, <2 → full.
  Проекция на verified subset: **128/203 FPs eliminated, 0 TPs
  false-suppressed**.
- **Poisoned-project-config** FP на `example.com` и URLs внутри MD
  code fences. Fix: IANA docs TLDs в exclusion list + strip fenced
  code blocks для .md файлов.
- **`render_json` cwd/git_branch leak** — Codex parser v0.7.7 правильно
  извлекал cwd из `session_meta.payload.cwd`, но reporter отбрасывал.
  Фикс: все Session fields попадают в JSON output.

**Реальный impact:** 871-finding MD: top section 91 KB / 1778 строк
vs 1.69 MB / 35935 строк flat (5% размера). Критические TPs видны
на первом scroll.

No rule IDs changed — still 27 total.

Следующее: **v0.8.1** — project-type awareness (`.agent-audit.yaml`
+ auto-detect по CLAUDE.md keywords). **v0.8.2** — Codex tool
normalization (canonical_tool field для cross-agent detector
compatibility).

### v0.7.7 — Sonnet default + Codex fixes *(готово)*

Три бага в Codex coverage найдены при анализе 871-finding отчёта + perf win.

- **Sonnet по умолчанию для Claude CLI backend** (2x faster, 3x cheaper
  чем Opus на verify workload). Override: `--claude-model opus`.
- **`unbounded-loop` polling whitelist** — `write_stdin(chars="")` это
  semantic READ от tmux session, не повторяющееся действие. Убирает 3/6 FP.
- **`dangerous-recommendation` skip на verifier JSON** — наш собственный
  output прошлого verify run не должен триггерить advice detector.
  Убирает ~3/5 FP.
- **Codex parser теперь извлекает `cwd` из правильного места** —
  `session_meta.payload.cwd` (primary, line 1) + `turn_context.payload.cwd`
  (per-turn fallback) + `exec_command.workdir` (last-resort). Раньше
  искали на top level что не совпадало с реальной Codex schema. Плюс
  `json.loads(..., strict=False)` для tolerance к raw control chars
  внутри `user_instructions` strings. Это чинит
  `AI-05.poisoned-project-config` на всех Codex сессиях.

Total: 27 rule IDs, без изменений.

### Уроки для v0.8 (не исполнены в v0.7.7)

- Power-law findings distribution: 10 сессий = 95% findings. UX overhaul.
- Project-type awareness (`.agent-audit.yaml`) для DAST/pentest workflow.
- Codex tool-name normalization (все C2/C3/AG detectors заточены под
  Claude Code event structure — на Codex пропускают сигнал).

### v0.7.6 — Markdown + verify timeout fixes *(готово)*

Два реальных бага из прогона Сергея на v0.7.5:

- **Markdown corruption:** `report.py` вложенные ``` ломали outer fence
  в .md отчёте. Fix через count longest backtick run + N+1 outer fence.
  Проверено на реальном 871-finding отчёте: 0 unclosed fences после fix.
- **Integrity review 120s timeouts:** implicit default timeout
  backend.call() был 120s. Integrity prompts 2× больше primary verify
  prompts; codex-cli под concurrency=4 с big prompts хитал timeout
  одновременно на нескольких batches.

Fix:
- `verify_batch` timeout default 120s → 240s, param-able
- `integrity_review` timeout default 300s
- `--timeout` CLI flag (default 240s)
- Integrity review throttles concurrency до `min(concurrency, 2)`
  + uses `timeout × 1.5`

No rule changes — same 27 rule IDs as v0.7.5.

### v0.7.5 — Cyber-class detectors + version audit *(готово)*

Первый релиз где threat model смещается от self-inflicted (over-reliance)
к cyber-sourced (agent как жертва или vector). Основан на Check Point
Research Feb 2026 disclosures + Cursor/MCP CVE landscape.

**2 новых детектора + 1 расширенный:**

- `AI-05.poisoned-project-config` (CRITICAL/HIGH/MEDIUM) — inverse
  of `mcp-config-mutation`. Сканирует `.claude/`, `.cursor/`,
  `.windsurf/`, `CLAUDE.md` *внутри* project dir (сessia.cwd) на
  shell-in-hook, STDIO-MCP, invisible unicode, sensitive path refs,
  external exfil URLs. Один scan на unique project root, bounded
  (≤30 files/project, ≤50 projects/run, ≤256KB/file). Ловит Check Point
  CVE-2025-59536 / CVE-2026-21852 class retroactively.

- `AI-05.agent-version-vulnerable` (severity per CVE) — reads installed
  agent CLI version via subprocess, сверяет с maintained table.
  Текущие entries: Claude Code ≤2.0.64 (CVE-2025-59536), Cursor ≤1.9.99
  (CVE-2025-54136). Zero-FP by construction.

- `persistence_write` extended — добавлены `.claude/hooks/*`,
  `.cursor/hooks/*`, `.windsurf/hooks/*`, `.codex/hooks/*`,
  `.continue/hooks/*`. Previously только `.git/hooks/`. Agent-tool
  hooks executable at project open — same persistence semantics.

**Total: 27 rule IDs** (было 25 в v0.7.4).

### v0.7.4 — Parallel verify + real-data calibration *(готово)*

Калибровка по 143-сессионному прогону (871 findings) реальных данных
CyberOK. Три failure modes + претензионный детектор дали 80% FP noise
и 30+ минут verify. Фиксим обе проблемы.

**Parallel verify infrastructure:**

- `batch_verifier.verify_all_batched` переписан на ThreadPoolExecutor
- Новый `--concurrency` flag (default 4)
- `--batch-size` default 10 → 25
- Integrity review тоже параллельный
- **Замеренный speedup 9.92x** на benchmark (bs=10 seq → bs=25 c=4)

**FP fixes по real-data clusters:**

- AG-04 `_is_ephemeral_only` теперь стопится на shell separator — фикс
  multi-stage `rm /tmp/X && python script.py` regression (закрывает 51/70)
- `AI-04.mcp-config-mutation` narrow'ed: только mcp.json / .cursorrules /
  system-level configs. Project-local CLAUDE.md и Claude Code memory
  больше не триггерят (закрывает 36/39)
- `behavior.hypothetical-executed` + imperative filter (EN/RU/ZH).
  "let's check X" больше не hypothetical (закрывает 1/1)
- `claim_detector` threshold 4 → 5. Verb + cross-category-object alone
  теперь остаётся `uncertain`, не `claim`. Нужен direct-category object
  или evidence anchor (закрывает 220/523, downgrades 261 HIGH → MEDIUM)

**Проекция на real data:** 871 → 563 findings (35% FP eliminated).

Без новых детекторов — фокус на calibration. Total остаётся 25 rule IDs.

### v0.7.3 — i18n + attachment failure modes + OX MCP research *(готово)*

**Multi-language NLU (RU/ZH):** `nlu/lexicons.py` с 3-язычными
лексиконами, `claim_detector` переписан под CJK substring + RU/EN
tokens. 11/11 RU + 8/8 ZH + 17/18 EN regression cases.

**Новые детекторы (5):**

- `behavior.confirmation-bypass` (HIGH/CRITICAL) — `--force`/`-y`/
  `--auto-approve`/`--accept-data-loss` на destructive cmd. Из GitHub
  issues #27063 (Railway drizzle), #34729 (Prisma reset), #4969 (Codex).
- `behavior.hypothetical-executed` (CRITICAL) — user спросил
  гипотетически, агент исполнил. Issue #28699.
- `AI-04.mcp-config-mutation` (CRITICAL/HIGH) — агент пишет в
  `mcp.json`/settings.json/CLAUDE.md/.cursorrules. OX Security research,
  CVE-2026-30615 (Windsurf).
- `credential.context-bleed` (HIGH/CRITICAL) — `export
  GOOGLE_APPLICATION_CREDENTIALS=~/Downloads/...` или cloud profile
  switch. Reddit r/ClaudeAI Apr 2026 case (25k docs deleted).
- `resource.api-storm` (MEDIUM/HIGH/CRITICAL) — same endpoint, varying
  args, >=25 calls. Reddit r/AI_Agents Apr 2026 (50k API / prod DB crash).

**Расширены существующие детекторы:**

- AG-04/cascading-destructive: Windows (`rmdir /s /q`, `Remove-Item`),
  macOS (`diskutil apfs deleteVolume`), migrations (drizzle/prisma/n8n)
- `cascading-destructive-chain`: добавлен Tier 0 diagnostic ops
  (pkill -9, rm *-wal, cache clear) для ловли n8n-style remediation chains
- `advice.dangerous-recommendation`: `wrapper-bypass` pattern —
  `npx -c`/`sh -c`/`python -c`/`eval` для обхода allowlist (OX Flowise)

**Total: 25 rule IDs** (было 22 в v0.7.2).

### v0.7.2 — Calibration from real data + composite C3 + CST *(готово)*

Калибровка по данным реального 108-сессионного прогона (Apr 2026), где
codex-cli верифицировал 256 findings и объяснял rationale каждого FP.
Из 79% FP rate снижаем до целевых ~30-35% через узкие фиксы на тупые
кластеры и структурные улучшения.

**Новое: Compact Sandbox Trace (CST).** Для каждого значимого autonomy
window собирается structured summary — control flow, taint chains,
sensitive paths, network endpoints, claims, per-category subgraph
scores, anomaly heuristic. Attach'ится к findings как Evidence в двух
форматах: Markdown (для .md отчёта) и JSON (для LLM верификатора).
Решает жалобу codex'а "alert omits the transfer target and data".

**Новое: NLU claim detector.** `nlu/claim_detector.py` — score-based
пайплайн из D+E+F+H+I+J+K+M+N тактик (sentence typing, category lexicons,
modality/hedge penalties, evidence anchors, three-bucket output).
94% accuracy на 18 regression cases из codex rationales. Stdlib only.

**Переписан C3 на composite правила:**

- `C3.autonomy-window-context` INFO — context pointer с CST, не alert
- `C3.autonomy-with-sensitive-sink` MEDIUM — window + sensitive write
- `C3.autonomy-with-exfil-chain` HIGH/CRITICAL — window + causality
  chain external source → non-shell sink (score >=0.5 / >=0.8)
- `C3.autonomy-with-persistence` HIGH — window + persistence write

**Quick fixes:**

- AG-04 `/tmp` filter — destructive на ephemeral paths skip'ается
  (закрывает 87/87 FP)
- AI-06 localhost filter — `127.0.0.1`/`localhost`/private IP больше
  не "external" (закрывает 51/82 FP)
- SSH probe evidence fix — snippet корректно описывает
  ssh-keygen verification (закрывает 2/2 FP)
- Unbounded-loop pytest whitelist — threshold 10 для test runners
  (закрывает 6/8 FP)

**Новое в src/:**

- `nlu/claim_detector.py`, `nlu/taint.py`, `nlu/filters.py`
- `cst.py` — Compact Sandbox Trace builder с JSON + Markdown рендером
- `EDR_BACKLOG.md` — что требует runtime telemetry и отложено до v1.0

### v0.7 — Chaos detectors + dangerous advice *(готово)*

Пять новых session-based детекторов из глубокого разбора 16 incidents
AiAIFail + 11 case studies Agents of Chaos. Закрывают те failure modes
которые config-only аудит не видит.

**Новые детекторы:**

- `behavior.unverified-completion-claim` — агент утверждает что сделал
  (committed/pushed/deployed/tests pass/migrated/fixed) без evidence в
  tool calls. 7 claim specs. Главный урок из ASAMM integrity-review и
  ключевая цитата из abstract Agents of Chaos: "agents reported task
  completion while the underlying system state contradicted those reports".
- `behavior.cascading-destructive-chain` — 3+ destructive actions с
  эскалацией tier'ов (T1→T4) в одной autonomy window. Из CS6 Agents
  of Chaos (guilt-trip → прогрессивное саморазрушение).
- `resource.unbounded-loop` — тот же tool + тот же input 4+ раз в одной
  window (MEDIUM), 8+ раз (HIGH). Из CS4 (9-дневный relay на 60K tokens)
  и CS5 (silent DoS через unbounded attachments).
- `AI-06.indirect-prompt-injection-vector` — external fetch (WebFetch,
  curl, Read CLAUDE.md/AGENTS.md/MEMORY.md и т.д.) → sensitive action
  без user turn между ними. Из CS10 (constitution GIST injection).
- `advice.dangerous-recommendation` — 10 классов опасных советов в
  assistant text: run-as-root, disable-firewall, chmod-777, tls-bypass,
  git-force-push, skip-tests, delete-no-backup, hardcoded-secret,
  curl-pipe-sh, wildcard-iam. Negation-aware ("never do X" не flag'ится).
  Из Meta SEV1 — incident из-за _совета_ агента, не из-за его действий.

**Все 5 детекторов** устанавливают `needs_llm_verification=True` —
recall-over-precision, LLM verifier фильтрует false positives.

### v0.6 — OSS imports: Aegis + AGT + LLM Guard *(готово)*

Импорт готовых сигнатурных баз из проверенных open-source проектов с
правильной атрибуцией. Никакого изобретения велосипеда.

**Импорт Aegis (MIT, antropos17/Aegis):**
- 107 agent profiles в `knowledge/aegis_agents.json`
- 180 known domains + 93 config paths + 260 process names
- 70 sensitive path rules в 8 категориях

**Импорт AGT MCP patterns (MIT, microsoft/agent-governance-toolkit):**
- 8 категорий regex в `knowledge/agt_mcp_patterns.py`

**Импорт LLM Guard approach (MIT, protectai/llm-guard):**
- Invisible unicode через stdlib `unicodedata`

**v0.6 детекторы:**
- `MCP-08.poisoned-tool-description` — AGT patterns
- `AI-05.invisible-unicode` — LLM Guard approach
- `C2.credential-exfil-chain` — интеграция с 70 Aegis rules
- Extended discovery — ~100 Aegis agents via `--extended`

### v0.8 — Canary tokens *(планируется)*

Из анализа OSS landscape: Rebuff единственный OSS-пример с canary tokens,
archived с мая 2025. Пустая ниша.

- `agent-audit plant-canaries` — создаёт приманки в ~/.ssh/, ~/.aws/, ~/.env
- Scan проверяет читались ли они в сессиях
- Zero FP rate, детерминированный сигнал

### v0.9 — HTML report + Mission interview *(планируется)*

- HTML single-page printable (как в ASAMM samples)
- Интерактивный mission interview в начале scan (5 вопросов)
- Severity recomputation по ответам owner'а

### v1.0 — EDR mode *(будущее)*

Переход от forensic к realtime: MCP proxy mode, continuous daemon
watching ~/.claude/projects/, active defense через auto-applied deny rules.

## OSS attribution

Все внешние данные импортируются verbatim с чёткими ссылками:

| Source | License | Usage | Location |
|--------|---------|-------|----------|
| antropos17/Aegis | MIT | 107 agents + 70 path rules | `knowledge/aegis_*` |
| microsoft/agent-governance-toolkit | MIT | MCP poisoning regex | `knowledge/agt_mcp_patterns.py` |
| protectai/llm-guard | MIT | Unicode category approach | `detectors/secrets_in_config.py` |
| OWASP AST10 | CC-BY-SA 4.0 | Reference taxonomy in findings | `references=[]` |

Когда upstream обновляется — re-import, не ручной merge.

## Detector inventory (v0.7.5)

| ID | Severity | Source | Added |
|----|----------|--------|-------|
| C2.credential-exfil-chain | CRITICAL/HIGH/MEDIUM/LOW | session | v0.1, Aegis integration v0.6 |
| C2.private-key-exfil | CRITICAL | session | v0.2 |
| credential.context-bleed | HIGH/CRITICAL | session | v0.7.3 — wrong-project creds |
| C3.autonomy-window-context | INFO | session | v0.7.2 — CST carrier |
| C3.autonomy-with-sensitive-sink | MEDIUM | session | v0.7.2 — composite |
| C3.autonomy-with-exfil-chain | HIGH/CRITICAL | session | v0.7.2 — causality-aware |
| C3.autonomy-with-persistence | HIGH | session | v0.7.2 — composite |
| behavior.user-interruptions | HIGH/MEDIUM | session | v0.1 |
| behavior.unverified-completion-claim | HIGH/MEDIUM/LOW | session | v0.7, NLU v0.7.2, i18n v0.7.3, tightened v0.7.4 |
| behavior.cascading-destructive-chain | CRITICAL | session | v0.7 (CS6), Tier 0 v0.7.3 |
| behavior.confirmation-bypass | HIGH/CRITICAL | session | v0.7.3 — --force/--yes |
| behavior.hypothetical-executed | CRITICAL | session | v0.7.3 — issue #28699, imperative fix v0.7.4 |
| resource.unbounded-loop | HIGH/MEDIUM | session | v0.7, pytest whitelist v0.7.2 |
| resource.api-storm | MEDIUM/HIGH/CRITICAL | session | v0.7.3 — endpoint pounding |
| advice.dangerous-recommendation | CRITICAL/HIGH/MEDIUM | session | v0.7 (Meta SEV1), wrapper-bypass v0.7.3 |
| AI-04.persistence-write | HIGH | session | v0.2, agent hooks v0.7.5 |
| AI-04.mcp-config-mutation | CRITICAL/HIGH | session | v0.7.3 — OX research / CVE-2026-30615, narrowed v0.7.4 |
| **AI-05.poisoned-project-config** | **CRITICAL/HIGH/MEDIUM** | session | **v0.7.5 — Check Point CVE-2025-59536** |
| **AI-05.agent-version-vulnerable** | **CRITICAL/HIGH per CVE** | config | **v0.7.5 — version audit** |
| AD-02.out-of-cwd-write | HIGH | session | v0.2 |
| AI-06.indirect-prompt-injection-vector | HIGH | session | v0.7, localhost fix v0.7.2 |
| AG-04.destructive-without-backup | CRITICAL/HIGH | session | v0.4, ephemeral v0.7.2, Win/mac v0.7.3, multi-stage v0.7.4 |
| AV-01.test-touches-prod | HIGH | session | v0.4 |
| AG-02.unversioned-mcp | MEDIUM | config | v0.5 |
| AI-05.secrets-in-agent-config | CRITICAL/HIGH | config | v0.5 |
| AI-05.invisible-unicode | HIGH | config | v0.6 (LLM Guard) |
| MCP-08.poisoned-tool-description | CRITICAL/HIGH | config | v0.6 (AGT) |
| MCP-08.poisoned-tool-description.schema | HIGH | config | v0.6 (AGT) |
| config.claude-code.permissive.* | CRITICAL/HIGH | config | v0.1/v0.5 |
| config.codex.permissive.* | HIGH | config | v0.1 |
| probe.ssh-key-unencrypted | HIGH | env probe | v0.5, evidence fix v0.7.2 |
| AD-03.adjacent-repo-reach | CRITICAL/HIGH | env probe (full) | v0.5 |

**Total: 27 rule IDs** across session/config/env-probe surfaces.

The AI-05 (Supply Chain) cluster now has 4 distinct rules covering
different sub-surfaces: `secrets-in-agent-config`, `invisible-unicode`,
`poisoned-project-config`, `agent-version-vulnerable`.

### v0.8 — Ensemble verification *(планируется)*

Когда доступно 2+ рабочих verifier'а — критичные findings проверяются
обоими. Disagreement = review человеком.

- Применимо только для critical/high (удваивает cost)
- Ценно для private-key-exfil, destructive-without-backup, cascading-destructive-chain
- Метрика inter-model agreement

## Matrix verifier backends

| Backend | Notes |
|---------|-------|
| claude -p (CLI) | Parses 403/401/429 from JSON body |
| codex exec (CLI) | npm i -g @openai/codex |
| Anthropic API | Direct HTTP via ANTHROPIC_API_KEY |
| OpenAI API | OPENAI_API_KEY |
| OpenRouter | OPENROUTER_API_KEY, works in RU |
| Ollama (local) | OLLAMA_MODEL=llama3.3 |
| Custom OpenAI-compat | LM Studio, vLLM, llama.cpp |

## Backlog (идеи без версии)

### AST Precision Plan

Подробный план введения markdown AST / tree-sitter / Rego лежит
отдельно: [docs/ast-precision-plan.md](docs/ast-precision-plan.md).

Кратко:
- **v0.12** — markdown-it-py prefilter для native detectors (measurable,
  reversible, локальный)
- **v0.13** — tree-sitter для fenced shell (conditional on v0.12)
- **v0.14** — feature extraction cache (refactor bridge)
- **v1.0** — Rego для maturity rollup (не для detection)

### ASAMM maturity rollup

Findings сейчас несут primary + secondary ASAMM controls в `references`,
но финальная L1/L2/L3 оценка не вычисляется. Это должна быть **пост-скан
корреляция** — отдельный модуль, который принимает findings stream и
ASAMM control catalog, выдаёт `{control_id: maturity_level}` + projected
trust grade (A-F × 1-6).

Open design questions перед реализацией:

- где живёт machine-readable ASAMM v0.3 control catalog (YAML/JSON)?
- какой threshold: "сколько HIGH на control X = downgrade maturity"?
- positive-evidence detection для L2+ (наличие tests/logs/docs, не только
  absence of findings)
- как сочетать session findings + project findings + config findings
  в один rollup

Оценка: 3-5 дней работы после того как collection-scale + subtree mode
закроют data quality. Engine выбора: **OPA/Rego** (см. AST Precision Plan D-4).

## Принципы

1. Прозрачность поверх магии — никаких silent fallbacks
2. Consent на expanded scope — явное согласие с точным описанием
3. Recall over precision в aggressive режиме — LLM разгребёт
4. Никогда не auto-apply — мы forensic tool, не active defense
5. Zero-dependency backends — urllib only
6. Integrity review > одиночного прохода — structural control
7. OSS over inventing — готовые MIT-сигнатуры лучше самописных
