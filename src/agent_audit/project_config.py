"""v0.8.1 — Project-type awareness.

Two sources of truth for project config, merged:

1. Auto-detect from CLAUDE.md / AGENTS.md / README.md keywords:
   - "DAST", "EASM", "vulnerability scanner", "pentest framework",
     "whitehat scanner", "bug bounty" → tags: [dast]
   - "malware analysis", "reverse engineering" → tags: [security-research]
   - "red team", "offensive security" → tags: [red-team]

2. Explicit `.agent-audit.yaml` at project root — overrides/extends
   auto-detected. Example:

     tags: [dast, zhet]
     trusted_targets:
       - testinvicti.com
       - juice-shop
       - checkxss.skipa.cyberok.ru
     severity_overrides:
       C3.autonomy-with-exfil-chain: info
       AI-06.indirect-prompt-injection-vector: info
     suppress_rules:
       - C3.autonomy-with-sensitive-sink
     allowlist_writes:
       - ~/.claude/projects/*/memory/
       - /tmp/zhet_*

Detectors consult the loaded config via `get_project_config(cwd)` —
cached per project root. Severity overrides applied in the Finding
emission path; trusted_targets checked when scoring network egress;
suppress_rules drops findings entirely; allowlist_writes skips
AD-02.out-of-cwd-write for matching paths.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

try:
    import yaml
except ImportError:
    yaml = None


CONFIG_FILENAME = ".agent-audit.yaml"
ALT_CONFIG_FILENAME = ".agent-audit.yml"


# Tag auto-detection patterns — matched against CLAUDE.md/AGENTS.md/README.md
# content. Multi-keyword for robustness; order matters (first match wins per
# tag).
_TAG_PATTERNS: Dict[str, re.Pattern] = {
    "dast": re.compile(
        r"""
        \b(?:
            DAST\b | EASM\b
          | vulnerability[\s-]?scanner
          | web[\s-]?vulnerability[\s-]?scanner
          | whitehat[\s-]?scanner
          | penetration[\s-]?testing[\s-]?(?:tool|framework|scanner)
          | bug[\s-]?bounty[\s-]?automation
          | security[\s-]?scanner
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "pentest-framework": re.compile(
        r"""
        \b(?:
            pentest[\s-]?framework
          | pentesting[\s-]?framework
          | offensive[\s-]?security[\s-]?framework
          | exploit[\s-]?framework
          | red[\s-]?team[\s-]?tool(?:kit)?
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "security-research": re.compile(
        r"""
        \b(?:
            malware[\s-]?analysis
          | reverse[\s-]?engineering
          | binary[\s-]?analysis
          | security[\s-]?research(?:er)?
          | threat[\s-]?intel
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
    "red-team": re.compile(
        r"""
        \b(?:
            red[\s-]?team
          | offensive[\s-]?security
          | adversary[\s-]?emulation
        )\b
        """,
        re.IGNORECASE | re.VERBOSE,
    ),
}


# Default severity downgrades per tag. If project has a tag, detectors
# listed here get the specified severity override (unless user explicitly
# overrides further via .agent-audit.yaml).
_DEFAULT_TAG_OVERRIDES: Dict[str, Dict[str, str]] = {
    "dast": {
        # DAST tools routinely trigger these on their own scan targets
        "C3.autonomy-with-exfil-chain": "info",
        "C3.autonomy-with-sensitive-sink": "info",
        "C3.autonomy-window-context": "info",  # already info, but explicit
        "AI-06.indirect-prompt-injection-vector": "info",
        # /etc/passwd probes, SSRF payloads in request bodies etc — all
        # legitimate DAST behavior
        "AG-04.destructive-without-backup": "low",
    },
    "pentest-framework": {
        "C3.autonomy-with-exfil-chain": "info",
        "C3.autonomy-with-sensitive-sink": "info",
        "AI-06.indirect-prompt-injection-vector": "info",
        "advice.dangerous-recommendation": "low",  # pentest tools discuss
                                                    # dangerous commands by design
    },
    "security-research": {
        "AI-06.indirect-prompt-injection-vector": "low",
        "advice.dangerous-recommendation": "low",
    },
    "red-team": {
        "C3.autonomy-with-exfil-chain": "info",
        "AI-06.indirect-prompt-injection-vector": "info",
        "advice.dangerous-recommendation": "low",
    },
}


@dataclass
class ProjectConfig:
    """Resolved configuration for one project root."""
    project_root: Path
    tags: List[str] = field(default_factory=list)
    trusted_targets: List[str] = field(default_factory=list)
    severity_overrides: Dict[str, str] = field(default_factory=dict)
    suppress_rules: Set[str] = field(default_factory=set)
    allowlist_writes: List[str] = field(default_factory=list)
    source: str = "default"  # "explicit" / "auto-detected" / "merged" / "default"

    def apply_severity_override(self, rule_id: str, original: str) -> str:
        """Return the overridden severity for a finding, or original if
        no override applies. Handles exact match and prefix match
        (e.g. config 'C3.*' matches C3.autonomy-*)."""
        if rule_id in self.severity_overrides:
            return self.severity_overrides[rule_id]
        # Prefix match
        for pattern, sev in self.severity_overrides.items():
            if pattern.endswith(".*") and rule_id.startswith(pattern[:-2]):
                return sev
        return original

    def is_suppressed(self, rule_id: str) -> bool:
        """True if finding should be dropped entirely."""
        if rule_id in self.suppress_rules:
            return True
        for pattern in self.suppress_rules:
            if pattern.endswith(".*") and rule_id.startswith(pattern[:-2]):
                return True
        return False

    def is_trusted_target(self, url_or_host: str) -> bool:
        """True if host/URL matches a trusted target (DAST scan target,
        deploy destination, etc)."""
        if not url_or_host:
            return False
        lo = url_or_host.lower()
        for target in self.trusted_targets:
            t = target.lower().strip()
            if not t:
                continue
            if t in lo:
                return True
        return False

    def is_allowed_write(self, path: str) -> bool:
        """True if a write to `path` should be allowed (not flagged as
        out-of-cwd, not flagged as persistence-sensitive, etc)."""
        if not path:
            return False
        for pattern in self.allowlist_writes:
            if fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(path, pattern + "/*"):
                return True
            # Also plain substring — handles mid-path patterns
            if pattern in path:
                return True
        return False


def _read_small_file(path: Path, max_bytes: int = 64 * 1024) -> Optional[str]:
    """Bounded read of a project doc file."""
    try:
        if not path.is_file():
            return None
        return path.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError:
        return None


def _auto_detect_tags(project_root: Path) -> List[str]:
    """Scan project docs for tag keywords."""
    doc_names = ["CLAUDE.md", "AGENTS.md", "AGENT.md", "README.md", "README.rst",
                 ".cursorrules", "GEMINI.md"]
    combined_text = ""
    for name in doc_names:
        content = _read_small_file(project_root / name)
        if content:
            combined_text += "\n" + content

    if not combined_text:
        return []

    tags = []
    for tag, pattern in _TAG_PATTERNS.items():
        if pattern.search(combined_text):
            tags.append(tag)
    return tags


def _load_explicit_config(project_root: Path) -> Optional[Dict]:
    """Load .agent-audit.yaml if present. Returns parsed dict or None."""
    if yaml is None:
        return None

    for fname in (CONFIG_FILENAME, ALT_CONFIG_FILENAME):
        path = project_root / fname
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                data = yaml.safe_load(content)
                if isinstance(data, dict):
                    return data
            except (OSError, yaml.YAMLError):
                continue
    return None


def _merge_tag_defaults(tags: List[str]) -> Tuple[Dict[str, str], List[str]]:
    """Merge default severity overrides from all matched tags.
    Returns (severity_overrides, merged_trusted_targets)."""
    overrides: Dict[str, str] = {}
    for tag in tags:
        tag_def = _DEFAULT_TAG_OVERRIDES.get(tag, {})
        # Later tags override earlier (conservative: most-specific-last)
        overrides.update(tag_def)
    return overrides, []


@lru_cache(maxsize=256)
def get_project_config(cwd: Optional[str]) -> ProjectConfig:
    """Return the resolved ProjectConfig for a given cwd. Results are
    cached per (resolved) project root across a single scan run.

    Resolution:
      1. If cwd is None or invalid → return default empty config
      2. Walk up from cwd looking for .agent-audit.yaml (stops at /)
      3. Auto-detect tags from project docs
      4. Merge: explicit yaml values override auto-detected, which
         override tag-default severity downgrades
    """
    if not cwd:
        return ProjectConfig(project_root=Path("/"))

    try:
        start = Path(cwd).resolve()
    except (OSError, RuntimeError):
        return ProjectConfig(project_root=Path(cwd))

    # Walk up looking for .agent-audit.yaml (search up to 6 levels)
    project_root = start
    found_explicit = None
    current = start
    for _ in range(6):
        for fname in (CONFIG_FILENAME, ALT_CONFIG_FILENAME):
            if (current / fname).is_file():
                found_explicit = current
                project_root = current
                break
        if found_explicit:
            break
        if current.parent == current:
            break
        current = current.parent

    if not found_explicit:
        project_root = start

    # Auto-detect tags from docs
    auto_tags = _auto_detect_tags(project_root)

    # Load explicit config
    explicit = _load_explicit_config(project_root) or {}

    # Merge
    explicit_tags = explicit.get("tags") or []
    if isinstance(explicit_tags, str):
        explicit_tags = [explicit_tags]
    all_tags = list(dict.fromkeys(auto_tags + [str(t) for t in explicit_tags]))

    # Tag-default severity overrides (auto from tags)
    tag_overrides, _ = _merge_tag_defaults(all_tags)

    # Explicit severity overrides layer on top
    explicit_overrides = explicit.get("severity_overrides") or {}
    if isinstance(explicit_overrides, dict):
        for k, v in explicit_overrides.items():
            tag_overrides[str(k)] = str(v).lower()

    trusted_targets = list(explicit.get("trusted_targets") or [])
    suppress = set(str(x) for x in (explicit.get("suppress_rules") or []))
    allowlist_writes = [str(x) for x in (explicit.get("allowlist_writes") or [])]

    source = "default"
    if found_explicit and auto_tags:
        source = "merged"
    elif found_explicit:
        source = "explicit"
    elif auto_tags:
        source = "auto-detected"

    return ProjectConfig(
        project_root=project_root,
        tags=all_tags,
        trusted_targets=trusted_targets,
        severity_overrides=tag_overrides,
        suppress_rules=suppress,
        allowlist_writes=allowlist_writes,
        source=source,
    )


def clear_cache() -> None:
    """Clear the cached project configs — useful for tests."""
    get_project_config.cache_clear()
