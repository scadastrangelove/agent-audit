# Third-party licenses

This project bundles data and regex patterns from three MIT-licensed
open-source projects. Their original copyright notices are reproduced
below, as required by the MIT License.

---

## 1. Aegis

**Repository:** https://github.com/antropos17/Aegis
**Bundled artifacts:**
- `src/agent_audit/knowledge/aegis_agents.json` (verbatim from `src/shared/agent-database.json`)
- `src/agent_audit/knowledge/aegis_rules/*.yaml` (verbatim from `rules/`)

**License text:**

```
MIT License

Copyright (c) 2026 AEGIS Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 2. Microsoft Agent Governance Toolkit (AGT)

**Repository:** https://github.com/microsoft/agent-governance-toolkit
**Bundled artifacts:**
- `src/agent_audit/knowledge/agt_mcp_patterns.py` (regex patterns adapted
  from `packages/agent-os/src/agent_os/mcp_security.py` — patterns are
  character-for-character identical; wrapping code is ours)

**License text:**

```
MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## 3. LLM Guard

**Repository:** https://github.com/protectai/llm-guard
**Bundled artifacts:**
- No code imported directly. The approach in
  `src/agent_audit/detectors/secrets_in_config.py` for invisible-unicode
  detection (using `unicodedata.category()` checks against Cf/Cc/Co) follows
  LLM Guard's `InvisibleText` scanner methodology. Implementation uses
  Python stdlib only; no LLM Guard code is linked.

**License text:**

```
MIT License

Copyright (c) 2023 Protect AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

---

## 4. Agent Threat Rules (ATR)

**Repository:** https://github.com/Agent-Threat-Rule/agent-threat-rules
**Bundled artifacts:**
- `src/agent_audit/knowledge/rule_packs/atr/**/*.yaml` — 233 detection rules
  adapted from ATR `main` (imported 2026-04-21). Regex patterns, test cases,
  and upstream references (OWASP LLM/Agentic, MITRE ATLAS, CVE) are
  character-for-character identical with the upstream files. Wrapping fields
  (`atr_source`, `agent_audit_id`, `audit_surface`, `asamm`) are agent-audit
  contributions.

**License text:**

```
MIT License

Copyright (c) 2026 ATR Contributors
```
(Full MIT text as above.)

---

## 5. Aguara (selective rules)

**Repository:** https://github.com/garagon/aguara
**Bundled artifacts:**
- `src/agent_audit/knowledge/rule_packs/external/aguara/**/*.yaml` — 37 rules
  from Aguara's `internal/rules/builtin/`, selected categories only
  (ssrf-cloud, third-party-content, external-download). Overlapping categories
  with ATR were deliberately excluded. Regex patterns and examples are
  character-for-character identical with the upstream YAML. Wrapping fields
  are agent-audit contributions.

**License:** Apache-2.0, Copyright (c) 2026 garagon.

---

## 6. Cisco PromptGuard rule pack (via Cisco AI Defense Skill Scanner)

**Repository:** https://github.com/cisco-ai-defense/skill-scanner
**Bundled artifacts:**
- `src/agent_audit/knowledge/rule_packs/external/cisco-promptguard/*.yaml` —
  26 detection rules from the PromptGuard pack bundled inside Cisco's
  skill-scanner (`skill_scanner/data/packs/promptguard/signatures/`).
  Categories: pii_exposure, secret_providers, markdown_exfil — chosen because
  they are absent from both ATR and Aguara. Regex patterns are
  character-for-character identical. Wrapping fields are agent-audit
  contributions.

**License:** Apache-2.0, Copyright 2026 Cisco Systems, Inc.

---

## References (not bundled, cited only)

- **OWASP Agentic Skills Top 10 (AST10)** — https://github.com/OWASP/www-project-agentic-skills-top-10
  Licensed CC-BY-SA-4.0. We cite AST01..AST10 IDs as severity/taxonomy
  references in Finding.references fields. No content bundled.

- **ASAMM** — https://github.com/scadastrangelove/asamm
  Methodology framework referenced throughout. Findings reference ASAMM
  control IDs (C2, C3, AI-04, etc.).
