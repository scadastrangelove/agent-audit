# Snippet to add to agent-audit/THIRD_PARTY_LICENSES.md
# (after the existing ATR entry at section 4)

---

## 5. Aguara (selective rules)

**Repository:** https://github.com/garagon/aguara
**Bundled artifacts:**
- `src/agent_audit/knowledge/external_rules/aguara/**/*.yaml` — 37 detection
  rules adapted from Aguara's `internal/rules/builtin/` directory, selected
  categories only (ssrf-cloud, third-party-content, external-download).
  Regex patterns, severity, and examples are character-for-character
  identical with the upstream YAML. Wrapping fields (`external_source`,
  `agent_audit_id`, `audit_surface`, `asamm`) are agent-audit contributions.

**License text:**

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

Copyright (c) 2026 garagon

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

---

## 6. Cisco PromptGuard rule pack (via Cisco AI Defense Skill Scanner)

**Repository:** https://github.com/cisco-ai-defense/skill-scanner
**Bundled artifacts:**
- `src/agent_audit/knowledge/external_rules/cisco-promptguard/*.yaml` —
  26 detection rules adapted from the PromptGuard rule pack as bundled in
  Cisco's skill-scanner (`skill_scanner/data/packs/promptguard/signatures/`).
  Categories: pii_exposure, secret_providers, markdown_exfil. Regex
  patterns, severity, and remediation text are character-for-character
  identical with the upstream YAML. Wrapping fields (`external_source`,
  `agent_audit_id`, `audit_surface`, `asamm`) are agent-audit contributions.

**License text (Cisco skill-scanner):**

```
Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

Copyright 2026 Cisco Systems, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0
```

The PromptGuard pack carries its own source attribution in each YAML
file (upstream: https://github.com/promptguard/promptguard). It is
redistributed as part of Cisco skill-scanner under Apache-2.0.
