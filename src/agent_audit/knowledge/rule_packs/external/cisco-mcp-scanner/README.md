# Cisco AI Defense mcp-scanner YARA rules (vendored)

YARA rules vendored from [cisco-ai-defense/mcp-scanner](https://github.com/cisco-ai-defense/mcp-scanner)
at commit fetched on 2026-05-08.

## License

Distributed under Apache 2.0. See `LICENSE` in this directory. Compatible
with agent-audit's MIT license — Apache 2.0 permits redistribution under
more permissive terms with attribution preserved.

## What it covers

10 YARA rule files targeting MCP **tool definitions** (name, description,
inputSchema). Designed for runtime tool inspection but applies equally
to manifest-discovered tool definitions because MCP protocol payloads
have the same shape.

| Rule file | Threat type |
|---|---|
| `code_execution.yara` | Code execution / RCE patterns |
| `coercive_injection.yara` | Coercive injection |
| `command_injection.yara` | Shell command injection |
| `credential_harvesting.yara` | API keys, SSH keys, env vars exfil |
| `data_exfiltration.yara` | Network exfil patterns |
| `prompt_injection.yara` | System-prompt override / role redefine |
| `script_injection.yara` | XSS, JS injection |
| `sql_injection.yara` | SQL injection patterns |
| `system_manipulation.yara` | OS command, privilege escalation |
| `tool_poisoning.yara` | MCP tool description poisoning |

## How agent-audit uses these

Loaded via `agent_audit.detectors.mcp_yara_scanner` when `yara-python` is
installed. agent-audit applies the rules against:

1. MCP tool **descriptions** discovered in manifests (`mcp.json`,
   `.mcp/server.json`, `.cursor/mcp_config.json`, etc.)
2. MCP tool **names**
3. MCP **prompt** definitions
4. MCP server **instructions** if shipped with the manifest

A YARA match produces an A5 finding (`A5.cisco-yara-<rule-name>`) with
severity derived from the `classification` meta field on the YARA rule.

## Updating

To refresh rules:

```bash
cd /tmp && rm -rf mcp-scanner
git clone --depth 1 https://github.com/cisco-ai-defense/mcp-scanner.git
cp /tmp/mcp-scanner/mcpscanner/data/yara_rules/*.yara \
   src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/yara_rules/
cp /tmp/mcp-scanner/LICENSE \
   src/agent_audit/knowledge/rule_packs/external/cisco-mcp-scanner/LICENSE
```

Then re-run the corpus eval to confirm no rule format breaks downstream.
