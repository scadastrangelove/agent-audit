# Security Policy

## Reporting a Vulnerability

If you believe you found a security issue in `agent-audit`, please report it
privately before opening a public issue.

Preferred private channels:

- GitHub Security Advisory, if the repository is hosted on GitHub
- email: `scadastrangelove@gmail.com`

Use private disclosure before opening a public issue.

Please include:

- affected version
- reproduction steps
- impact assessment
- whether the issue can expose secrets, modify files, or misclassify security findings

## Response Expectations

- initial acknowledgement target: within 3 business days
- status update target: within 7 business days
- coordinated disclosure preferred after a fix or mitigation exists

## Scope

We especially care about:

- code execution or unsafe parsing from scanned content
- secret leakage in logs, reports, or verifier prompts
- verifier / report integrity issues that misstate findings
- packaging or release issues that ship unsafe artifacts

## Out of Scope

- theoretical issues with no practical reproduction
- feature requests or detection gaps without a concrete security impact
