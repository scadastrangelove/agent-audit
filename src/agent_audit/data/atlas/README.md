# MITRE ATLAS data snapshot

Vendored from <https://github.com/mitre-atlas/atlas-data> for offline
validation of `mitre_atlas:*` references in our rule packs and native
detectors.

- **Source**: `mitre-atlas/atlas-data`, `dist/ATLAS.yaml`
- **License**: Apache-2.0, Copyright 2021–2025 MITRE. See `LICENSE`.
- **Refresh cadence**: quarterly, or on-demand when ATLAS releases a
  major rev.

## Refresh procedure

```bash
git clone --depth 1 https://github.com/mitre-atlas/atlas-data.git /tmp/atlas-data
cp /tmp/atlas-data/dist/ATLAS.yaml \
   src/agent_audit/data/atlas/ATLAS.yaml
cp /tmp/atlas-data/LICENSE \
   src/agent_audit/data/atlas/LICENSE
python -m agent_audit.tools.atlas_validate
# review any new issues, fix references in our rule YAMLs as needed
```

## Why vendor

`agent-audit` runs offline by default. Fetching ATLAS data over HTTP at
validation time would break that contract. The snapshot is small
(~450KB) and the validator runs in milliseconds. Drift detection is
therefore a hygiene check, not a runtime dependency.

## Current snapshot

Run `python -m agent_audit.tools.atlas_validate` and the printed
`ATLAS version:` line is authoritative. As of last refresh: ATLAS v5.6.0.
