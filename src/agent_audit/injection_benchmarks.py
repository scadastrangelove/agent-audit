# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""Prompt-injection benchmark adapter — Roadmap items D2 (AgentDyn) + D3 (WASP).

These benchmarks ship as full agent-execution frameworks (AgentDyn extends
AgentDojo; WASP wraps WebArena). Running their full evaluation pipelines
requires the agent harness, the web environments, and external API keys —
out of scope for our static rule-pack measurement.

What we DO want from them is the labelled corpus of injection text
strings: each test case carries an attacker instruction (the malicious
prompt the agent sees in third-party content). Running our rule packs
against those strings tells us:

  - **recall**: how many known-malicious injection prompts our patterns
    detect at all.
  - **per-pack contribution**: which packs (NOVA, ATR, Aguara) catch
    which injection styles. This is informative for Aguara FP rate
    calibration and for the M3 NOVA evaluator decision matrix.

We do NOT measure precision from these benchmarks. The benchmarks ship
malicious cases; benign cases come from a separate corpus (we have our
own benign-skill corpus already used in calibration).

## Licensing

- AgentDyn: MIT (the SaFo-Lab/AgentDyn repo). Safe to bundle in our
  CI test fixtures if we ever need offline regression. For now we
  read from a user-cloned local checkout to keep our repo lean.
- WASP: CC-BY-NC 4.0 for the data portion. **We do NOT bundle WASP
  data.** The adapter reads from a user-cloned local checkout. The
  resulting metrics can be published in academic papers (we use the
  data internally for measurement) but the data itself stays in the
  user's clone.

## Why not pip-install the upstream packages

AgentDyn's `pyproject.toml` pulls in 60+ runtime dependencies including
playwright, openai, anthropic SDKs, and full agentdojo. WASP pulls in
selenium, webarena, visualwebarena. None of that matters for static
prompt-string measurement — we only need the strings. Reading from a
local checkout via filesystem walk is leaner and license-friendlier.

## Output shape

The adapter loads a corpus and returns a list of `InjectionCase`
objects. The `BenchmarkRunner` then runs every rule pack pattern
against each case's text and counts matches per (rule_id, case_id)
pair. Output is a structured report with:

  - per-suite recall (cases with at least one rule firing / total)
  - per-rule contribution (cases each rule fires on)
  - hardest cases (no rule fired) — useful for paper analysis

This is intentionally simple. It's not a replacement for the upstream
benchmark — it's a measurement of how our static layer fares against
the *text* of those cases, treated as adversarial input documents.
"""
from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple


# ----------------------------------------------------------------------------
# Data types
# ----------------------------------------------------------------------------

@dataclass
class InjectionCase:
    """Single injection test case from an upstream benchmark."""
    case_id: str        # e.g. "agentdyn:v1_2/workspace/InjectionTask3"
    suite: str          # "agentdyn" | "wasp"
    text: str           # the attacker's instruction string
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class CaseResult:
    case_id: str
    suite: str
    rules_fired: List[str]   # rule_ids that matched the injection text
    text_preview: str

    @property
    def detected(self) -> bool:
        return bool(self.rules_fired)


@dataclass
class BenchmarkReport:
    suite: str
    total_cases: int = 0
    detected_cases: int = 0
    per_rule_hits: Dict[str, int] = field(default_factory=dict)
    undetected: List[CaseResult] = field(default_factory=list)
    detected: List[CaseResult] = field(default_factory=list)

    @property
    def recall(self) -> float:
        if not self.total_cases:
            return 0.0
        return self.detected_cases / self.total_cases

    def to_dict(self) -> dict:
        return {
            "suite": self.suite,
            "total_cases": self.total_cases,
            "detected_cases": self.detected_cases,
            "recall": round(self.recall, 4),
            "per_rule_hits": dict(
                sorted(self.per_rule_hits.items(), key=lambda kv: -kv[1])
            ),
            "undetected_count": len(self.undetected),
            "undetected_sample": [
                {"case_id": r.case_id, "preview": r.text_preview}
                for r in self.undetected[:10]
            ],
        }


# ----------------------------------------------------------------------------
# AgentDyn loader — extract GOAL strings via AST walk
# ----------------------------------------------------------------------------

def _extract_class_attribute(class_node: ast.ClassDef, attr_name: str) -> Optional[str]:
    """Pull a string-valued class attribute. Handles plain string, f-string,
    and string concatenation via formatted values.

    AgentDyn's GOAL fields are typically f-strings with template variables
    that resolve at class instantiation. We can't fully resolve them
    statically, but we can recover the literal portions which contain the
    injection-relevant prose.
    """
    for stmt in class_node.body:
        # Pattern: GOAL = "..."  or  GOAL: str = "..."
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            target = stmt.targets[0]
            if isinstance(target, ast.Name) and target.id == attr_name:
                return _flatten_string_node(stmt.value)
        if isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and stmt.target.id == attr_name:
                if stmt.value is not None:
                    return _flatten_string_node(stmt.value)
    return None


def _flatten_string_node(node: ast.AST) -> Optional[str]:
    """Best-effort flatten of a string-shaped AST node into a literal-or-
    placeholder text. Names inside f-strings become "{name}" placeholders
    so the resulting text is still searchable for the literal portions
    of the prompt."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        # f-string. Rebuild flattening FormattedValue → "{expr}" placeholder.
        parts: List[str] = []
        for v in node.values:
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                parts.append(v.value)
            elif isinstance(v, ast.FormattedValue):
                # Use a stable placeholder so rule-pack patterns that
                # match prose around the placeholder still fire.
                try:
                    expr = ast.unparse(v.value)
                except Exception:
                    expr = "?"
                parts.append("{" + expr + "}")
            else:
                parts.append("")
        return "".join(parts)
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        # String concatenation: "..." + "..."
        left = _flatten_string_node(node.left)
        right = _flatten_string_node(node.right)
        if left is not None and right is not None:
            return left + right
    return None


def load_agentdyn_cases(repo_root: Path) -> List[InjectionCase]:
    """Walk an AgentDyn checkout for InjectionTask classes and harvest
    their GOAL strings.

    `repo_root` should be the path to a clone of github.com/SaFo-Lab/AgentDyn.
    We look under `src/agentdojo/default_suites/*/*/injection_tasks.py`,
    matching the upstream layout.

    Returns one InjectionCase per InjectionTask class found.
    """
    cases: List[InjectionCase] = []
    if not repo_root.exists():
        return cases

    candidate = repo_root / "src" / "agentdojo" / "default_suites"
    if not candidate.exists():
        # Some clones live at the bare root — try direct
        candidate = repo_root
    pattern = candidate.rglob("injection_tasks.py")

    for path in pattern:
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue

        # Path components: ".../default_suites/v1_X/<suite>/injection_tasks.py"
        try:
            rel = path.relative_to(repo_root)
        except ValueError:
            rel = path
        rel_parts = list(rel.parts)
        # Drop trailing "injection_tasks.py"
        suite_parts = rel_parts[:-1]
        suite_label = "/".join(suite_parts[-2:]) if len(suite_parts) >= 2 else "/".join(suite_parts)

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if "Injection" not in node.name and "Inject" not in node.name:
                continue
            goal = _extract_class_attribute(node, "GOAL")
            if not goal:
                continue
            # Resolve a class-level _RECIPIENT/_SENDER reference if present
            goal = _resolve_class_constants(node, goal)
            cases.append(InjectionCase(
                case_id=f"agentdyn:{suite_label}/{node.name}",
                suite="agentdyn",
                text=goal,
                metadata={"source_file": str(rel)},
            ))
    return cases


def _resolve_class_constants(class_node: ast.ClassDef, text: str) -> str:
    """Best-effort substitute class-level string constants like _RECIPIENT
    into the GOAL placeholder. This recovers more of the literal injection
    text for matching."""
    constants: Dict[str, str] = {}
    for stmt in class_node.body:
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
            t = stmt.targets[0]
            if isinstance(t, ast.Name) and t.id.startswith("_"):
                v = _flatten_string_node(stmt.value)
                if v is not None:
                    constants[t.id] = v
    # Substitute "{self._FOO}" or "{self.FOO}" patterns
    out = text
    for name, val in constants.items():
        out = out.replace("{self." + name + "}", val)
        out = out.replace("{" + name + "}", val)
    return out


# ----------------------------------------------------------------------------
# WASP loader — read injection instructions from experiment config JSON
# ----------------------------------------------------------------------------

def load_wasp_cases(repo_root: Path) -> List[InjectionCase]:
    """Read WASP injection cases from
    `webarena_prompt_injections/configs/experiment_config.raw.json` in
    the user's clone.

    Each entry's `instruction` field is the injection text. We tag with
    `environment` (gitlab/reddit/etc) and `exfil` boolean as metadata.
    """
    cases: List[InjectionCase] = []
    if not repo_root.exists():
        return cases

    config_path = (
        repo_root / "webarena_prompt_injections" / "configs"
        / "experiment_config.raw.json"
    )
    if not config_path.exists():
        return cases

    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return cases

    entries = data.get("prompt_injections_setup_config") or []
    if not isinstance(entries, list):
        return cases

    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            continue
        instruction = str(entry.get("instruction") or "").strip()
        if not instruction:
            continue
        # Resolve simple {placeholder} patterns from `parameters` so the
        # injection text is closer to its actual deployed form
        parameters = entry.get("parameters") or {}
        if isinstance(parameters, dict):
            for k, v in parameters.items():
                instruction = instruction.replace("{" + k + "}", str(v))
        name = str(entry.get("free_form_name") or f"case_{i}")
        env = str(entry.get("environment") or "?")
        cases.append(InjectionCase(
            case_id=f"wasp:{env}:{name}",
            suite="wasp",
            text=instruction,
            metadata={
                "environment": env,
                "exfil": str(entry.get("exfil", False)),
            },
        ))
    return cases


# ----------------------------------------------------------------------------
# Runner — apply rule packs to each case, build report
# ----------------------------------------------------------------------------

def _evaluate_case(case: InjectionCase, rules: list) -> CaseResult:
    """Run every static-applicable rule pack pattern against the case text,
    collect rule_ids that match. exclude_patterns are honored — we want the
    same false-positive suppression as production scans."""
    text = case.text
    fired: List[str] = []
    for r in rules:
        if not r.patterns:
            continue
        # Honor excludes first
        if any(exc.search(text) for exc in r.exclude_patterns):
            continue
        for pat in r.patterns:
            if pat.search(text):
                fired.append(r.agent_audit_id)
                break
    preview = re.sub(r"\s+", " ", text).strip()[:140]
    return CaseResult(
        case_id=case.case_id,
        suite=case.suite,
        rules_fired=fired,
        text_preview=preview,
    )


def run_benchmark(
    cases: Iterable[InjectionCase],
    *,
    rules: Optional[list] = None,
    suite_label: str = "combined",
) -> BenchmarkReport:
    """Run rule packs against the supplied cases and produce a report.

    `rules` defaults to `load_all_rules()`. Pass an explicit subset for
    faster tests or focused measurement (e.g. NOVA-only).
    """
    if rules is None:
        from .knowledge.rule_pack_loader import load_all_rules
        rules = load_all_rules()

    cases_list = list(cases)
    report = BenchmarkReport(suite=suite_label, total_cases=len(cases_list))
    for case in cases_list:
        result = _evaluate_case(case, rules)
        if result.detected:
            report.detected_cases += 1
            report.detected.append(result)
            for rid in result.rules_fired:
                report.per_rule_hits[rid] = report.per_rule_hits.get(rid, 0) + 1
        else:
            report.undetected.append(result)
    return report
