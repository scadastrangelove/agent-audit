"""Project scanner — apply rule-pack rules to a directory of repos.

Different from the session-based scanner (scanner.py):
- Input: a filesystem path — single repo or directory containing repos
- No session parsing, no agent discovery
- Uses the external rule packs (ATR, Aguara, Cisco PromptGuard) via
  rule_pack_loader

File surface classification: each file is mapped to one or more
audit_surface categories based on path/name, then only rules declaring
a matching surface are applied. This keeps execution bounded even for
296 rules × N files.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, List, Optional, Set

from .knowledge.rule_pack_loader import RulePackRule, load_all_rules
from .knowledge.educational_suppressor import is_educational_context, demote_severity
from .knowledge.markdown_features import extract as extract_md_features
from .knowledge.rule_surface_classifier import classify_rule_surface
from .knowledge.agent_task_adapter import is_agent_task_config, extract_instruction_text
from .detectors import identity_redefinition, no_approval_model
from .rules import Confidence, Evidence, Finding, Severity


# -----------------------------------------------------------------------------
# Surface classification
# -----------------------------------------------------------------------------

# Instruction files that agents read. Matches any dir depth.
_INSTRUCTION_FILE_NAMES = {
    "AGENTS.md", "CLAUDE.md", "GEMINI.md", "COPILOT.md",
    ".cursorrules", ".windsurfrules",
}
_INSTRUCTION_FILE_GLOBS = [
    "**/.github/copilot-instructions.md",
    "**/.github/instructions/*.instructions.md",
]

# MCP manifests
_MCP_MANIFEST_NAMES = {"mcp.json", ".mcp.json"}
_MCP_MANIFEST_GLOBS = [
    "**/.claude/mcp.json",
    "**/.cursor/mcp.json",
    "**/.vscode/mcp.json",
    "**/claude_desktop_config.json",
]

# Plugin manifests
_PLUGIN_MANIFEST_GLOBS = [
    "**/.claude-plugin/plugin.json",
    "**/.codex-plugin/plugin.json",
    "**/.cursor-plugin/plugin.json",
]

# Skills live in conventional directories
_SKILL_MD_GLOBS = [
    "**/skills/**/SKILL.md",
    "**/.claude/skills/**/SKILL.md",
    "**/.codex/skills/**/SKILL.md",
    "**/.cursor/skills/**/SKILL.md",
    "**/composio-skills/**/SKILL.md",
    "**/SKILL.md",
]

# Text file extensions to read for generic pattern matching
_TEXT_EXTENSIONS = {".md", ".mdc", ".txt", ".json", ".yaml", ".yml", ".toml"}

# Skip noisy / vendor directories
_SKIP_DIRS = {
    ".git", "node_modules", "dist", "build", "__pycache__",
    ".venv", "venv", ".tox", ".mypy_cache", ".pytest_cache",
    "target", "out",
}

# Project-scan-applicable surfaces. Session-only surfaces are excluded —
# they require live session events, which the project scanner doesn't have.
_PROJECT_SURFACES = {
    "instruction_file",
    "mcp_manifest",
    "plugin_manifest",
    "skill_md",
    "tool_description",
    "agent_task_config",
}


def _classify_file(path: Path, repo_root: Path) -> Set[str]:
    """Which audit_surface categories does this file belong to?

    A file can belong to multiple surfaces (e.g., SKILL.md is both
    'skill_md' and 'instruction_file').
    """
    surfaces: Set[str] = set()
    name = path.name
    rel = path.relative_to(repo_root).as_posix() if path.is_absolute() else path.as_posix()

    # SKILL.md → skill_md + instruction_file
    if name == "SKILL.md":
        surfaces.add("skill_md")
        surfaces.add("instruction_file")

    # Known instruction files
    if name in _INSTRUCTION_FILE_NAMES:
        surfaces.add("instruction_file")

    # Plugin manifests first (more specific than mcp)
    if "plugin.json" in name and any(
        marker in rel for marker in (".claude-plugin", ".codex-plugin", ".cursor-plugin")
    ):
        surfaces.add("plugin_manifest")

    # MCP manifests
    if name in _MCP_MANIFEST_NAMES:
        surfaces.add("mcp_manifest")
    if "claude_desktop_config.json" in name or "/mcp.json" in rel or rel.endswith(".mcp.json"):
        surfaces.add("mcp_manifest")

    # Generic glob matches via fnmatch-style (pathlib match is stricter but ok)
    # Check instruction-file globs
    for pattern in _INSTRUCTION_FILE_GLOBS:
        if path.match(pattern):
            surfaces.add("instruction_file")

    # If file path contains '/tools/' and is json/yaml, treat as tool description
    # (used by MCP servers that ship per-tool descriptor files)
    if path.suffix.lower() in {".json", ".yaml", ".yml"} and "/tools/" in rel:
        surfaces.add("tool_description")

    # D-9: Agent-task YAML configs (multi-agent frameworks: AgentVerse, AutoGen,
    # CrewAI). Signature-detected to avoid FP on docker-compose / CI yaml.
    if path.suffix.lower() in {".yaml", ".yml"}:
        # Only check if path hints at agent-task context (fast reject)
        if any(hint in rel.lower() for hint in ("/tasks/", "/agents/", "/prompts/",
                                                  "/personas/", "/workflows/")):
            if is_agent_task_config(path):
                surfaces.add("agent_task_config")
                surfaces.add("instruction_file")  # run instruction-surface rules too

    return surfaces


def _is_text_file(path: Path) -> bool:
    return path.suffix.lower() in _TEXT_EXTENSIONS or path.name in (
        _INSTRUCTION_FILE_NAMES | _MCP_MANIFEST_NAMES
    )


def _walk_project_files(root: Path) -> Iterable[Path]:
    """Yield relevant files under root, skipping vendor/build dirs."""
    if root.is_file():
        yield root
        return
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        current = Path(dirpath)
        for filename in filenames:
            p = current / filename
            if _is_text_file(p):
                yield p


# -----------------------------------------------------------------------------
# Matching
# -----------------------------------------------------------------------------

def _safe_read(path: Path, max_bytes: int = 256 * 1024) -> Optional[str]:
    try:
        if path.stat().st_size > max_bytes:
            return None
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _match_rule_in_text(rule: RulePackRule, text: str) -> Optional[re.Match]:
    """Return the first matching pattern, or None.

    Semantics match the 'any' condition used by ATR / Aguara / Cisco PG:
    a rule fires if ANY of its patterns matches and NO exclude pattern matches.
    """
    # Exclude gate: if any exclude matches, suppress
    for exc in rule.exclude_patterns:
        if exc.search(text):
            return None
    for pat in rule.patterns:
        m = pat.search(text)
        if m:
            return m
    return None


def _snippet_around(text: str, match: re.Match, context: int = 60) -> str:
    start = max(0, match.start() - context)
    end = min(len(text), match.end() + context)
    s = text[start:end].replace("\n", " ")
    s = re.sub(r"\s+", " ", s).strip()
    return (("…" + s) if start > 0 else s) + (("…") if end < len(text) else "")


# -----------------------------------------------------------------------------
# Public API
# -----------------------------------------------------------------------------

@dataclass
class ProjectScanResult:
    repos_scanned: List[Path] = field(default_factory=list)
    files_scanned: int = 0
    files_with_findings: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


def _discover_repos(root: Path) -> List[Path]:
    """If root is a single repo (contains .git or a known instruction file),
    treat it as one repo. Otherwise treat each subdirectory with .git as a repo,
    or fall back to scanning root as one project."""
    if root.is_file():
        return [root]
    if (root / ".git").exists():
        return [root]

    # Recursively discover sibling repos. This matters for corpus layouts like:
    # corpus/category1/repo/.git, corpus/category2/repo/.git, ...
    # We prune descent once a repo root is found so nested vendor repos don't
    # explode the scan.
    subrepos: List[Path] = []
    if root.is_dir():
        for dirpath, dirnames, _filenames in os.walk(root):
            current = Path(dirpath)
            if ".git" in dirnames:
                subrepos.append(current)
                dirnames[:] = []  # don't descend into this repo
                continue
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
    if subrepos:
        return sorted(subrepos)
    # Fallback: treat root as a single project directory
    return [root]


def scan_project(
    path: Path,
    *,
    rules: Optional[List[RulePackRule]] = None,
    on_progress: Optional[Callable[[str], None]] = None,
    aggregate_collections: bool = True,
) -> ProjectScanResult:
    """Scan a filesystem path with rule packs. Returns ProjectScanResult.

    When aggregate_collections=True (default), findings that repeat across
    a cohort of sibling skills are collapsed into a single aggregate
    finding — see collection_scale.aggregate() for logic.
    """
    rules = rules if rules is not None else load_all_rules()
    # Only apply rules with at least one project-applicable surface
    applicable_rules = [r for r in rules if r.audit_surface & _PROJECT_SURFACES]

    result = ProjectScanResult()
    repos = _discover_repos(path)
    result.repos_scanned = repos

    for repo in repos:
        if on_progress:
            on_progress(f"scanning {repo.name}")
        for file_path in _walk_project_files(repo):
            surfaces = _classify_file(file_path, repo)
            if not surfaces:
                continue  # file not classified — no rules will match anyway
            text = _safe_read(file_path)
            if text is None:
                continue
            result.files_scanned += 1
            file_has_finding = False
            # Check educational context once per file
            edu_context = is_educational_context(file_path, text)

            # P0 A: for markdown files, compute prose/code views once and route
            # rules to the appropriate view. Non-markdown files (json/yaml
            # manifests) use raw text for all rules — they don't have the
            # prose/code distinction in the same form.
            is_markdown = file_path.suffix.lower() in {".md", ".mdc"}
            if is_markdown:
                features = extract_md_features(text)
                prose_view = features.text_without_code if features.ast_available else text
                # Concatenate all code blocks for matching
                code_view = "\n\n".join(
                    b for bs in features.code_blocks_by_lang.values() for b in bs
                ) if features.ast_available else text
            else:
                prose_view = text
                code_view = text

            for rule in applicable_rules:
                if not (rule.audit_surface & surfaces):
                    continue

                # Route by category — only for markdown files, non-markdown
                # keeps the 'both' (raw text) path.
                if is_markdown:
                    surface_pref = classify_rule_surface(rule)
                else:
                    surface_pref = "both"

                if surface_pref == "code":
                    match_text = code_view
                elif surface_pref == "prose":
                    match_text = prose_view
                else:
                    match_text = text

                m = _match_rule_in_text(rule, match_text)
                if m is None:
                    continue

                refs: List[str] = []
                if rule.asamm_primary:
                    refs.append(f"ASAMM:{rule.asamm_primary}")
                for s in rule.asamm_secondary:
                    refs.append(f"ASAMM:{s}")
                # Upstream references (CVE/OWASP/MITRE) for the top-N
                for kind, values in (rule.references or {}).items():
                    if isinstance(values, list):
                        for v in values[:3]:
                            refs.append(f"{kind}:{v}")
                refs.append(f"upstream:{rule.source_tool}:{rule.source_original_id}")
                if is_markdown and surface_pref != "both":
                    refs.append(f"surface-route:{surface_pref}")

                # Fix 3: suppress rule-pack findings in educational / translation
                # context unless structural skill markers say otherwise.
                effective_severity = rule.severity
                if edu_context:
                    effective_severity = Severity(demote_severity(rule.severity.value))
                    refs.append("suppressor:educational-context")

                result.findings.append(
                    Finding(
                        rule_id=rule.agent_audit_id,
                        title=rule.title,
                        severity=effective_severity,
                        confidence=Confidence.MEDIUM,
                        summary=f"[{rule.source_tool}] {rule.title} — matched in {file_path.relative_to(repo)}",
                        evidence=[
                            Evidence(
                                description=f"Pattern matched in {', '.join(sorted(surfaces & rule.audit_surface))}",
                                source=file_path,
                                snippet=_snippet_around(match_text, m),
                            )
                        ],
                        remediation=rule.remediation or None,
                        references=refs,
                        needs_llm_verification=(effective_severity in (Severity.MEDIUM, Severity.LOW)),
                    )
                )
                file_has_finding = True
            if file_has_finding:
                result.files_with_findings += 1

            # Native detectors (not from rule packs). Independent of audit_surface
            # match — these have their own file applicability rules.
            #
            # D-9: for agent-task YAML configs, native detectors need the
            # extracted prompt text (concatenated prompt-bearing fields), not
            # the raw YAML. Without this, lexicon patterns never match because
            # the surface is buried in YAML structure. bypass_applies_to lets
            # the YAML filename pass the detector's file-name gate.
            is_agent_task = "agent_task_config" in surfaces
            if is_agent_task:
                native_text = extract_instruction_text(file_path, text)
            else:
                native_text = text

            for idf in identity_redefinition.check_file(
                file_path, text=native_text, bypass_applies_to=is_agent_task
            ):
                result.findings.append(identity_redefinition.convert_to_finding(idf))
                if not file_has_finding:
                    result.files_with_findings += 1
                    file_has_finding = True
            for approval_f in no_approval_model.check_file(
                file_path, text=native_text, bypass_applies_to=is_agent_task
            ):
                result.findings.append(no_approval_model.convert_to_finding(approval_f))
                if not file_has_finding:
                    result.files_with_findings += 1
                    file_has_finding = True

    # Post-processing: collapse high-replication findings into aggregates
    if aggregate_collections and result.findings:
        from . import collection_scale
        result.findings = collection_scale.aggregate(result.findings)

    return result
