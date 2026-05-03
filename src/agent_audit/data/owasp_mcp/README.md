# OWASP MCP Top 10 data snapshot

Vendored from <https://github.com/OWASP/www-project-mcp-top-10> for
offline reference of `owasp_mcp:*` IDs in our rule packs and native
detectors.

- **Source**: `OWASP/www-project-mcp-top-10`, `2025/MCP*.md`
- **License**: CC BY-SA 4.0, OWASP Foundation. See `LICENSE.md`.
  Attribution preserved in `owasp_mcp_top10.yaml` (`source` field).
- **Status (upstream)**: v0.1-beta as of 2026.
- **Refresh cadence**: quarterly, or on-demand when OWASP MCP releases
  a major rev.

## Files in this directory

- `MCP01-2025-…md` … `MCP10-2025-…md` — verbatim upstream markdown,
  one per category. CC BY-SA 4.0 attribution preserved.
- `owasp_mcp_top10.yaml` — generated machine-readable index with id /
  title / description per category. Used by the validator and by
  `finding_dedup.canonical_class_for_owasp_mcp`. Do not edit by hand —
  regenerate with `python -m agent_audit.tools.owasp_mcp_index_build`.
- `LICENSE.md` — upstream CC BY-SA 4.0 license text.

## Refresh procedure

```bash
git clone --depth 1 https://github.com/OWASP/www-project-mcp-top-10.git /tmp/owasp-mcp
cp /tmp/owasp-mcp/2025/MCP*.md \
   src/agent_audit/data/owasp_mcp/
cp /tmp/owasp-mcp/LICENSE.md \
   src/agent_audit/data/owasp_mcp/LICENSE.md
python -m agent_audit.tools.owasp_mcp_index_build
python -m agent_audit.tools.owasp_mcp_validate
# review any new issues, fix references in our rule YAMLs as needed
```

## Why a CC BY-SA work in this repo

OWASP MCP Top 10 is licensed CC BY-SA 4.0. Our project license is MIT
for code and documentation. The two licenses coexist when CC BY-SA
material is kept in a clearly delimited subdirectory with attribution
preserved — which is what we do here. The CC BY-SA license applies
*only* to the markdown files and the generated index in this directory.
The validator code under `agent_audit/tools/` and the mapping module
under `agent_audit/knowledge/owasp_mcp_mapping.py` are MIT, derived
from our own analysis of which rule categories correspond to which MCP
risks — not from the OWASP text.

If you redistribute the contents of `data/owasp_mcp/`, you must comply
with CC BY-SA 4.0 (preserve attribution, share derivatives under a
compatible license).
