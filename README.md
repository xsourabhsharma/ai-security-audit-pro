# AI Security Audit Pro Plugin

> Universal security-audit plugin for AI agents. Turn Codex, Claude Code, Gemini CLI, Antigravity, OpenCode, Hermes, OpenClaw, or any shell-capable AI tool into a structured defensive security-audit operator.

![CI](https://github.com/xsourabhsharma/ai-security-audit-pro/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)
![OWASP](https://img.shields.io/badge/OWASP-ASVS%20%7C%20Top%2010%20%7C%20WSTG-111827.svg)
![Plugin Ready](https://img.shields.io/badge/plugin--ready-Codex%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Hermes%20%7C%20OpenClaw-0f766e.svg)

AI Security Audit Pro Plugin is a powerful defensive security-audit plugin and CLI engine for codebases, websites, and APIs. It gives AI agents a repeatable workflow for scoped security testing, scanner orchestration, evidence collection, false-positive triage, and professional report generation.

It is built for AI-assisted security work where quality matters: exact scope, clear authorization, redacted evidence, OWASP mapping, confidence levels, safe validation steps, and clean reports that can be reviewed by engineers or clients.

## Why This Plugin Exists

Most AI agents can read code. That does not make them reliable security auditors.

Security audits need a workflow:

- Scope the exact target.
- Confirm authorization before active testing.
- Check code, dependencies, secrets, headers, TLS, CORS, cookies, routes, APIs, and exposed paths.
- Run optional scanners without turning raw scanner noise into fake findings.
- Separate confirmed findings from likely findings and needs-validation findings.
- Produce a report with evidence, risk, impact, remediation, and residual risk.

AI Security Audit Pro Plugin packages that workflow so any supported agent can use it consistently.

## Plugin First, CLI Powered

AI platforms do not share one plugin standard. Codex, Claude Code, Gemini CLI, OpenCode, Hermes, OpenClaw, and Antigravity all load tools differently.

This repository solves that by shipping two layers:

| Layer | Purpose |
|---|---|
| Plugin and agent instructions | Tell AI tools when and how to use Security Audit Pro. |
| Universal CLI engine | Provides one stable command interface every shell-capable agent can run. |

The command line is not a fallback. It is the plugin runtime.

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

Any AI agent can call that command, inspect the generated report, validate the evidence, and explain the findings.

## Supported AI Agents

| Agent or tool | Integration included |
|---|---|
| Codex | `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `AGENTS.md` |
| Claude Code | `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` and CLI workflow |
| Google Antigravity | `GEMINI.md` or `agent-adapters/antigravity.md` |
| OpenCode | `AGENTS.md` or `agent-adapters/opencode.md` |
| Hermes | `agent-adapters/hermes.md` and CLI command-tool workflow |
| OpenClaw | `agent-adapters/openclaw.md` and CLI workflow |
| Any other AI tool | Universal prompt plus CLI command interface |

Universal prompt for any AI agent:

```text
Use AI Security Audit Pro Plugin from this repository. Run node scripts/security-audit.mjs against the exact target. Keep the audit defensive, authorized, and non-destructive. Redact secrets. Separate confirmed findings from likely or needs-validation findings. Produce Markdown plus HTML when requested, and explain skipped checks or residual risk.
```

## What It Audits

| Area | Checks |
|---|---|
| Source code | Injection hotspots, unsafe execution, XSS sinks, SSRF hotspots, file access, deserialization, XML parser risks, auth review hotspots. |
| Secrets | Redacted checks for API keys, tokens, private keys, JWTs, cloud keys, and secret-like assignments. |
| Dependencies | npm, pnpm, yarn, pip-audit, Bandit, OSV-Scanner, govulncheck, cargo-audit, composer audit when available. |
| Websites | Headers, TLS, cookies, CORS, HTTP methods, exposed files, debug endpoints, API docs, security.txt. |
| APIs | OpenAPI/Swagger/GraphQL/Postman artifact discovery, route inventory, authorization hotspots. |
| Active scans | Authorized httpx, SSLyze, katana, ffuf, Nuclei, and OWASP ZAP orchestration when installed. |
| Business logic | Scope template for roles, object authorization, uploads, quotas, sharing, admin actions, and workflow abuse testing. |
| Reports | Markdown, HTML dashboard, PDF, and JSON. |

## What Makes It Powerful

- **Universal agent compatibility:** one plugin package for many AI tools.
- **Professional bug-analysis output:** not just a scanner dump.
- **OWASP-aligned findings:** Top 10, API Top 10, ASVS, WSTG, CWE where practical.
- **Evidence-driven triage:** confirmed, likely, needs-validation, skipped, and false-positive-aware output.
- **Safe PoC guidance:** validation steps designed for defensive testing.
- **External scanner orchestration:** use serious tools when they are installed, skip cleanly when they are not.
- **JSON for automation:** agents can parse reports, rank findings, compare scans, and build workflows.
- **Local and hosted targets:** codebase scans, localhost apps, staging sites, and authorized public targets.

No honest tool can promise to find every vulnerability. This plugin is designed to find high-signal issues, preserve evidence, and make remaining gaps explicit.

## Install

Clone and verify:

```bash
git clone https://github.com/xsourabhsharma/ai-security-audit-pro.git
cd ai-security-audit-pro
npm test
```

Install globally from GitHub:

```bash
npm install -g github:xsourabhsharma/ai-security-audit-pro
security-audit-pro --target .
```

Requirements:

- Node.js 18 or newer.
- Optional: Python plus ReportLab for PDF output.
- Optional scanner tools on PATH for deeper coverage.

## Commands Agents Can Run

Local project audit:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

Authorized website audit:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

Deep authorized active scan:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

Machine-readable JSON for AI workflows:

```bash
node scripts/security-audit.mjs --target . --json --out report.json
```

## Modes

| Mode | Best for | Notes |
|---|---|---|
| `passive` | Local projects and low-risk URL posture checks. | Does not perform active probing. |
| `standard` | Authorized websites where shallow exposure checks are allowed. | Requires `--authorized`. |
| `active` | Authorized security reviews where scanner orchestration is allowed. | Requires `--authorized`. |

Active profiles:

- `safe`: lower volume.
- `balanced`: default profile.
- `deep`: broader non-destructive coverage for explicitly authorized targets.

## Report Output

Reports are designed to look like professional security assessment deliverables.

```text
Bug Analysis Report
  Assessment Conclusion
  Finding Overview
  Key Risk Summary
  Scope And Authorization
  Auth And Business Logic Scope
  Critical Severity Findings
  High Severity Findings
  Medium Severity Findings
  Low Severity Findings
  Info Severity Findings
  Reviewed Surfaces
  Coverage Matrix
  Tool Execution
  Skipped Checks And Residual Risk
```

Finding entries include:

```text
Status: Confirmed / Likely / Needs validation
Severity: Critical / High / Medium / Low / Info
Affected surface: file, URL, endpoint, header, route, or workflow
Evidence: redacted and reviewable
Risk: why this matters
Impact: what an attacker could gain
Mapping: OWASP / CWE where practical
Remediation: how to fix it
Safe validation: non-destructive reproduction or confirmation step
```

## Optional Scanner Tooling

The plugin works without bundled scanner binaries. Install tools separately and keep them on PATH, or set `SECURITY_AUDIT_TOOLS_DIR`.

Supported optional tools:

- Semgrep
- OSV-Scanner
- Gitleaks
- TruffleHog
- npm, pnpm, yarn audit
- pip-audit
- Bandit
- govulncheck
- cargo-audit
- composer audit
- ProjectDiscovery httpx
- katana
- ffuf
- Nuclei
- SSLyze
- OWASP ZAP
- Docker for ZAP Docker baseline

When tools are missing, the report records that clearly instead of pretending coverage happened.

## Repository Layout

```text
ai-security-audit-pro/
  .codex-plugin/plugin.json
  .claude-plugin/plugin.json
  agent-adapters/
  assets/
  docs/
  examples/
  scripts/security-audit.mjs
  skills/security-audit/SKILL.md
  templates/authenticated-audit-scope.md
  AGENTS.md
  CLAUDE.md
  GEMINI.md
```

## Safety

Use this plugin only on systems you own or are explicitly authorized to test.

Do not use it for credential attacks, denial of service, persistence, stealth, malware, data dumping, or testing outside approved scope.

A clean report means "no issues found by these checks." It does not prove the target has no vulnerabilities. Review coverage, skipped checks, and manual validation notes.

## Development

```bash
npm test
node scripts/security-audit.mjs --help
node scripts/security-audit.mjs --target . --mode passive --no-tools --json --out self-audit.json
```

## License

MIT. See [LICENSE](LICENSE).
