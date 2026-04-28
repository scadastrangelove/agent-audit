# Snippet to add to agent-audit/THIRD_PARTY_LICENSES.md

---

## 4. Agent Threat Rules (ATR)

**Repository:** https://github.com/Agent-Threat-Rule/agent-threat-rules
**Bundled artifacts:**
- `src/agent_audit/knowledge/atr_rules/**/*.yaml` — 233 detection rules adapted
  from ATR v0.1.0 / `main` (imported 2026-04-21). Regex patterns, test cases,
  and upstream references (OWASP LLM/Agentic, MITRE ATLAS, CVE) are
  character-for-character identical with the upstream files. Wrapping fields
  (`atr_source`, `agent_audit_id`, `audit_surface`, `asamm`) are agent-audit
  contributions and not derived from ATR.

**License text:**

```
MIT License

Copyright (c) 2026 ATR Contributors

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
