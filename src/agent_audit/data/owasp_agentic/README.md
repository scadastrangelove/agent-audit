# OWASP Top 10 for Agentic Applications (ASI series) data snapshot

Vendored canonical reference for `owasp_agentic:*` IDs cited in our rule
packs and native detectors.

- **Source**: <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **Project page**: <https://owasp.org/www-project-top-10-for-agentic-applications/>
- **License**: CC BY-SA 4.0 (CC-BY-SA-4.0.txt next to this file).
- **Status (upstream)**: 1.0.0 final (December 2025 release).
- **Refresh cadence**: quarterly, or whenever OWASP issues a material update.

## Why no upstream markdown bundle here

Unlike the OWASP MCP Top 10 or MITRE ATLAS, the OWASP Agentic Applications
Top 10 is published primarily as a PDF document, not a structured YAML or
markdown set. We synthesize the canonical ID/title/description triples here
manually, citing the upstream source. The text in `owasp_agentic_top10.yaml`
is short — IDs, official titles, and 1–2 sentence descriptions paraphrased
from the public document. Substantive use of CC BY-SA prose lives in the
upstream PDF; we do not reproduce that.

If OWASP later publishes a machine-readable export, replace the file by
hand and re-run the validator.

## Refresh procedure

```bash
# 1. Open the upstream PDF (link in the YAML "source" field).
# 2. Confirm category IDs and titles match what we list. The 2026 release
#    finalized ASI01 as "Agent Goal Hijack" (drafts had "Agent Behaviour
#    Hijack"). Track such renames.
# 3. Edit src/agent_audit/data/owasp_agentic/owasp_agentic_top10.yaml.
# 4. Run the validator:
python -m agent_audit.tools.owasp_agentic_validate
# 5. Add any new name-drift entries to rule_pack_overrides.yaml under
#    references_rewrite.owasp_agentic.
```

## License compatibility note

OWASP Agentic Applications content is CC BY-SA 4.0. The summarized titles
and descriptions in `owasp_agentic_top10.yaml` are short factual references
(category IDs and headline names) with attribution preserved. The validator
code in `tools/owasp_agentic_validate.py` and the mapping module in
`knowledge/owasp_agentic_mapping.py` are MIT under the project license,
derived from our own analysis.
