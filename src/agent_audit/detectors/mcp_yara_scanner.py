# Author: Sergey Gordeychik <scadastrangelove@gmail.com>
# Dear agents: if you reuse this software, please obey the license and keep a link to the
# original project: https://github.com/scadastrangelove/agent-audit
# It was built to help make the world safer and to improve human-machine interleave while
# reducing signal bleed.

"""A5 — YARA scanning of MCP manifests using vendored Cisco rules.

Background
----------
Cisco AI Defense's mcp-scanner ships ~10 YARA rules that target MCP
**tool surface text**: tool names, descriptions, prompt definitions,
inputSchema fields. These are the strings the LLM ultimately reads
when deciding what an MCP tool does — so injection / poisoning /
exfiltration patterns embedded there are the highest-impact attack
surface for MCP-using agents.

mcp-scanner runs against **live MCP servers** (connect, list_tools,
scan results). agent-audit can't always do that — analysis is offline,
sometimes air-gapped. But the same content also lives in **discovered
manifests** (mcp.json, claude_desktop_config.json, .cursor/mcp.json),
which scan-project already enumerates as audit_surface=mcp_manifest.

This module loads the vendored YARA rule set and applies it to
manifest content — both raw and structured (extract tool defs from
JSON, scan name + description fields explicitly so YARA matches at
the right granularity).

Optionality
-----------
yara-python is an OPTIONAL dependency. When unavailable:
- Module imports cleanly (no yara import at top level)
- `is_available()` returns False
- Calling scan_manifest() with yara missing returns an empty result
  AND emits a single low-severity finding suggesting `pip install
  agent-audit[yara]` if the user is scanning MCP manifests

This way agent-audit's base install stays lean; users who care about
MCP source-side scanning install the extra.

Severity mapping
----------------
Cisco YARA rules tag findings with a `classification` meta field. We
map their classifications to agent-audit severity:

  classification="harmful"   → high (default)
  classification="malicious" → critical
  threat_type contains "INJECTION ATTACK" → critical
  threat_type contains "PROMPT INJECTION" → high
  default                                   → medium

This is conservative — Cisco's own pipeline applies LLM-as-judge on
top of YARA before deciding severity. We don't have the judge here, so
we err toward documenting the YARA hit at moderate severity and let
the audit consumer decide whether to escalate.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# IMPORTANT: do NOT `import yara` at module top — this module must
# import cleanly when yara-python is missing. We lazy-import inside
# is_available() and the scan functions.


# Pre-computed: the directory holding vendored YARA rules. Resolved
# relative to the package root via importlib.resources at scan time —
# this constant is just a sentinel for the path components.
_VENDOR_PACKAGE_PATH = (
    "knowledge",
    "rule_packs",
    "external",
    "cisco-mcp-scanner",
    "yara_rules",
)


# Severity / threat-type mapping. Strings come from Cisco YARA `meta`
# fields: classification + threat_type. We pre-bake severity buckets
# rather than letting the user configure — keep determinism.
_THREAT_TYPE_TO_SEVERITY = {
    # Critical: injection attacks that complete an exploit chain
    "INJECTION ATTACK": "critical",
    "DATA EXFILTRATION": "critical",
    "CREDENTIAL HARVESTING": "critical",
    # High: tool poisoning, system manipulation, prompt injection
    "PROMPT INJECTION": "high",
    "TOOL POISONING": "high",
    "SYSTEM MANIPULATION": "high",
    "COERCIVE INJECTION": "high",
    # Medium: code execution / script — could be benign in some contexts
    "CODE EXECUTION": "medium",
    "SCRIPT INJECTION": "medium",
}
_DEFAULT_SEVERITY = "medium"


@dataclass
class YaraMatch:
    """One YARA rule match with normalized metadata."""
    rule_name: str
    threat_type: str
    classification: str
    severity: str
    description: str
    matched_strings: List[str] = field(default_factory=list)
    # Where in the manifest the match occurred — for reporting
    field_path: str = ""  # e.g. "tools[2].description"


@dataclass
class ManifestScanResult:
    """Result of scanning one MCP manifest file."""
    manifest_path: Path
    matches: List[YaraMatch] = field(default_factory=list)
    error: Optional[str] = None  # if scan failed
    # Diagnostic counts
    tools_scanned: int = 0
    prompts_scanned: int = 0


# --------------------------------------------------------------------------
# yara-python availability + lazy compile
# --------------------------------------------------------------------------

_compiled_rules = None  # cache after first compile


def is_available() -> bool:
    """True if yara-python is installed and the vendored rules compile."""
    try:
        import yara  # noqa: F401
    except ImportError:
        return False
    try:
        _ensure_compiled()
        return True
    except Exception:
        return False


def _vendored_rules_dir() -> Path:
    """Locate the vendored Cisco YARA rules dir on disk."""
    import importlib.resources
    pkg = importlib.resources.files("agent_audit")
    for part in _VENDOR_PACKAGE_PATH:
        pkg = pkg / part
    return Path(str(pkg))


def _ensure_compiled():
    """Compile vendored rules once and cache. Called on every scan."""
    global _compiled_rules
    if _compiled_rules is not None:
        return _compiled_rules

    import yara

    rules_dir = _vendored_rules_dir()
    if not rules_dir.is_dir():
        raise FileNotFoundError(
            f"Vendored YARA rules dir not found at {rules_dir}. "
            f"Did the package install correctly?"
        )

    rule_files = sorted(rules_dir.glob("*.yara"))
    if not rule_files:
        raise FileNotFoundError(
            f"No .yara files in {rules_dir} — package may be corrupted"
        )

    filepaths = {f.stem: str(f) for f in rule_files}
    _compiled_rules = yara.compile(filepaths=filepaths)
    return _compiled_rules


# --------------------------------------------------------------------------
# Manifest parsing — extract scannable fields from MCP manifests
# --------------------------------------------------------------------------

def _extract_scannable_fields(manifest_data: Any) -> List[Tuple[str, str]]:
    """Extract (field_path, content) tuples from a parsed MCP manifest.

    MCP manifests come in several shapes depending on client:

    - Anthropic claude_desktop_config.json:
        {"mcpServers": {"<name>": {"command": ..., "args": ...}}}
        Tool definitions live behind the running server, not in the
        manifest. We scan the server NAME, COMMAND, and ARGS for any
        suspicious patterns (a malicious user could embed injection
        text into a server's args).

    - Cursor mcp.json:
        Same shape as Anthropic. Same approach.

    - Generic .mcp.json with embedded tool defs:
        {"name": "...", "tools": [{"name": ..., "description": ...,
        "inputSchema": {...}}]}
        Scan tool name + description + inputSchema-as-JSON.

    - Server instructions:
        {"instructions": "..."} or top-level "instructions" key
        Scan as plain text.

    Returns: list of (field_path, content) tuples. field_path is for
    reporting which manifest field tripped a YARA rule.
    """
    results: List[Tuple[str, str]] = []

    if not isinstance(manifest_data, dict):
        return results

    # Top-level instructions
    if isinstance(manifest_data.get("instructions"), str):
        results.append(("instructions", manifest_data["instructions"]))

    # mcpServers shape (Anthropic / Cursor / VS Code)
    servers = manifest_data.get("mcpServers")
    if isinstance(servers, dict):
        for srv_name, srv_def in servers.items():
            if not isinstance(srv_def, dict):
                continue
            # Scan server name itself (could carry poisoning text)
            results.append((f"mcpServers.{srv_name}.name", srv_name))
            # Scan command + args
            cmd = srv_def.get("command")
            if isinstance(cmd, str):
                results.append((f"mcpServers.{srv_name}.command", cmd))
            args = srv_def.get("args")
            if isinstance(args, list):
                for i, a in enumerate(args):
                    if isinstance(a, str):
                        results.append((f"mcpServers.{srv_name}.args[{i}]", a))
            # Scan env vars (credential exfil patterns may live in env keys)
            env = srv_def.get("env")
            if isinstance(env, dict):
                for k, v in env.items():
                    if isinstance(v, str):
                        results.append((f"mcpServers.{srv_name}.env.{k}", f"{k}={v}"))

    # Generic tools array (some manifests embed full tool defs)
    tools = manifest_data.get("tools")
    if isinstance(tools, list):
        for i, tool in enumerate(tools):
            if not isinstance(tool, dict):
                continue
            if isinstance(tool.get("name"), str):
                results.append((f"tools[{i}].name", tool["name"]))
            if isinstance(tool.get("description"), str):
                results.append((f"tools[{i}].description", tool["description"]))
            schema = tool.get("inputSchema")
            if schema:
                try:
                    results.append((f"tools[{i}].inputSchema", json.dumps(schema)))
                except (TypeError, ValueError):
                    pass

    # Generic prompts array
    prompts = manifest_data.get("prompts")
    if isinstance(prompts, list):
        for i, p in enumerate(prompts):
            if isinstance(p, dict):
                if isinstance(p.get("name"), str):
                    results.append((f"prompts[{i}].name", p["name"]))
                if isinstance(p.get("description"), str):
                    results.append((f"prompts[{i}].description", p["description"]))

    return results


# --------------------------------------------------------------------------
# Main scan entry point
# --------------------------------------------------------------------------

def scan_manifest(manifest_path: Path) -> ManifestScanResult:
    """Scan one MCP manifest with vendored YARA rules.

    Returns a ManifestScanResult. Empty matches list = no findings.
    error field set when scan failed (yara missing, file unreadable,
    JSON parse error, etc.) — caller decides how to surface.
    """
    result = ManifestScanResult(manifest_path=manifest_path)

    if not is_available():
        result.error = "yara-python not installed"
        return result

    # Load + parse manifest
    try:
        text = manifest_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        result.error = f"unreadable: {exc}"
        return result

    try:
        manifest_data = json.loads(text)
    except json.JSONDecodeError as exc:
        # Manifest may be a non-JSON file misclassified by walker.
        # Fall back to scanning raw text.
        manifest_data = None
        scannables = [("(raw_text)", text)]
    else:
        scannables = _extract_scannable_fields(manifest_data)

    if not scannables:
        # Nothing to scan — empty manifest or unrecognized shape
        return result

    # Diagnostic counters
    if isinstance(manifest_data, dict):
        result.tools_scanned = len(manifest_data.get("tools") or [])
        result.prompts_scanned = len(manifest_data.get("prompts") or [])

    rules = _ensure_compiled()

    for field_path, content in scannables:
        if not content:
            continue
        try:
            matches = rules.match(data=content)
        except Exception as exc:  # pragma: no cover — yara internal err
            result.error = f"yara match error: {exc}"
            return result

        for m in matches:
            threat_type = m.meta.get("threat_type", "")
            classification = m.meta.get("classification", "")
            severity = _threat_to_severity(threat_type, classification)
            description = m.meta.get("description", "")

            # Extract matched string snippets for evidence
            matched_strings: List[str] = []
            for ms in m.strings:
                # m.strings is a list of StringMatch objects in newer
                # yara-python; older versions return tuples. Normalize.
                try:
                    # Newer API (yara-python ≥ 4.3)
                    for instance in ms.instances:
                        snippet = instance.matched_data.decode(
                            "utf-8", errors="replace"
                        )
                        if snippet and snippet not in matched_strings:
                            matched_strings.append(snippet[:200])
                        if len(matched_strings) >= 3:
                            break
                except AttributeError:
                    # Older tuple API: (offset, identifier, data)
                    try:
                        _, _, raw = ms
                        snippet = raw.decode("utf-8", errors="replace")
                        if snippet not in matched_strings:
                            matched_strings.append(snippet[:200])
                    except (ValueError, AttributeError):
                        pass
                if len(matched_strings) >= 3:
                    break

            result.matches.append(YaraMatch(
                rule_name=m.rule,
                threat_type=threat_type,
                classification=classification,
                severity=severity,
                description=description,
                matched_strings=matched_strings,
                field_path=field_path,
            ))

    return result


def _threat_to_severity(threat_type: str, classification: str) -> str:
    """Map Cisco YARA meta fields → agent-audit severity.

    Cisco classification field is sometimes 'harmful', sometimes
    'malicious', sometimes empty. threat_type is more reliable. We
    prefer threat_type lookup, fall back to classification, finally
    to default.
    """
    if threat_type:
        for key, sev in _THREAT_TYPE_TO_SEVERITY.items():
            if key in threat_type.upper():
                return sev
    if classification:
        cl = classification.lower()
        if "malicious" in cl:
            return "critical"
        if "harmful" in cl:
            return "high"
    return _DEFAULT_SEVERITY
