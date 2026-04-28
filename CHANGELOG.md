# Changelog

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

## Previous History

Historical iteration notes remain in `README.md` and project docs from the
research phase. They can be split further in a later documentation cleanup.
