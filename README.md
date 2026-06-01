# AI Security Audit Pro

![CI](https://github.com/xsourabhsharma/ai-security-audit-pro/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)
![OWASP](https://img.shields.io/badge/OWASP-ASVS%20%7C%20Top%2010%20%7C%20WSTG-111827.svg)
![Agent Ready](https://img.shields.io/badge/agent--ready-Codex%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenCode-0f766e.svg)

Agent-ready defensive security auditing for web apps, APIs, and local codebases. AI Security Audit Pro gives Codex, Claude Code, Gemini CLI, Google Antigravity, OpenCode, Hermes, OpenClaw, and other agents a shared security-audit workflow that produces professional Markdown, HTML, PDF, or JSON reports.

The core is a portable Node.js CLI, so any AI agent that can run shell commands can use it. Codex and Claude Code metadata are included, plus instruction files for Gemini CLI, Antigravity, OpenCode, Hermes, and OpenClaw.

## Why This Exists

Most AI agents can review code, but security audits need structure: scope, authorization, evidence, false-positive triage, safe validation steps, and a report that does not overclaim. This project packages that workflow into one reusable tool.

Use it for:

- Local source-code security review.
- Website and API security posture checks.
- OWASP-style bug analysis reports.
- Secret exposure checks with redacted evidence.
- Dependency and lockfile vulnerability review.
- Authorized active scans with common open-source tools.
- Agent-assisted triage for confirmed, likely, and needs-validation findings.

## Features

- **Agent-ready:** Codex, Claude Code, Gemini CLI, Antigravity, OpenCode, Hermes, OpenClaw, and generic agents.
- **Professional reports:** Markdown, HTML dashboard, PDF, and JSON output.
- **OWASP mapping:** OWASP Top 10, OWASP API Security Top 10, ASVS, WSTG, and CWE where practical.
- **Local SAST-style checks:** High-signal patterns for injection, unsafe deserialization, SSRF hotspots, file access, CORS, XSS sinks, and more.
- **Secret scanning:** Redacted regex checks, with optional Gitleaks or TruffleHog if installed.
- **Dependency checks:** Uses available ecosystem scanners such as npm audit, pip-audit, OSV-Scanner, Bandit, govulncheck, cargo-audit, and composer audit.
- **Website checks:** Headers, TLS, cookies, CORS, HTTP methods, exposed paths, API docs discovery, and security.txt.
- **Authorized active mode:** Can orchestrate httpx, SSLyze, katana, ffuf, Nuclei, and OWASP ZAP when installed.
- **Business-logic planning:** Includes an authenticated audit scope template for roles, object access, uploads, quotas, admin workflows, and API testing.
- **False-positive discipline:** Reports coverage, skipped checks, residual risk, and validation status.

## Quick Start

Requirements:

- Node.js 18 or newer.
- Optional: Python plus ReportLab for PDF output.
- Optional external scanners on PATH: Semgrep, OSV-Scanner, Gitleaks, TruffleHog, httpx, katana, ffuf, Nuclei, SSLyze, OWASP ZAP, Docker.

Clone and test:

```bash
git clone https://github.com/xsourabhsharma/ai-security-audit-pro.git
cd ai-security-audit-pro
npm test
```

Run a local project audit:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

Run an authorized website audit:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

Run a deeper authorized active scan:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

Machine-readable JSON:

```bash
node scripts/security-audit.mjs --target . --json --out report.json
```

Install as a global CLI from GitHub:

```bash
npm install -g github:xsourabhsharma/ai-security-audit-pro
security-audit-pro --target .
```

## Operating Modes

| Mode | Purpose | Hosted target requirement |
|---|---|---|
| `passive` | Local checks and one fetch of the supplied URL. | No active probing. |
| `standard` | Passive checks plus shallow exposure checks. | Requires `--authorized`. |
| `active` | Authorized scanner orchestration and bounded crawling/content discovery. | Requires `--authorized`. |

Active profiles:

- `safe`: lower request volume.
- `balanced`: default.
- `deep`: broader non-destructive coverage for explicitly authorized targets.

## Agent Support

| Agent | How to use |
|---|---|
| Codex | Uses `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `AGENTS.md`. |
| Claude Code | Uses `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `CLAUDE.md`. |
| Gemini CLI | Use `GEMINI.md` and call the CLI. |
| Google Antigravity | Use `GEMINI.md` or `agent-adapters/antigravity.md`. |
| OpenCode | Use `AGENTS.md` or `agent-adapters/opencode.md`. |
| Hermes | Use `agent-adapters/hermes.md` and register the CLI as a local command tool. |
| OpenClaw | Use `agent-adapters/openclaw.md` and call the CLI. |
| Any shell-capable agent | Run `node scripts/security-audit.mjs --target <target>`. |

More detail: [docs/agent-integration.md](docs/agent-integration.md).

Universal agent prompt:

```text
Use AI Security Audit Pro from this repository. Run node scripts/security-audit.mjs against the exact target. Keep the audit defensive and non-destructive. Redact secrets. Confirm authorization before active testing. Separate confirmed findings from likely or needs-validation findings. Produce Markdown plus HTML when requested.
```

## Report Output

Reports include:

- Assessment conclusion.
- Finding overview.
- Key risk summary.
- Scope and authorization.
- Auth and business-logic scope.
- Critical, high, medium, low, and info findings.
- Evidence, risk, impact, remediation, OWASP/CWE mapping, confidence, and safe validation steps.
- Reviewed surfaces.
- Coverage matrix.
- Tool execution details.
- Skipped checks and residual risk.

## Optional Tooling

This repository intentionally does not ship large scanner binaries. Install external tools separately and keep them on PATH, or set `SECURITY_AUDIT_TOOLS_DIR`.

Supported optional tools:

- Semgrep
- OSV-Scanner
- Gitleaks
- TruffleHog
- Nuclei
- ProjectDiscovery httpx
- katana
- ffuf
- SSLyze
- OWASP ZAP
- Docker for ZAP Docker baseline

The CLI still works without these tools and records skipped external checks in the report.

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

## Responsible Use

Only scan systems you own or are explicitly authorized to test. Do not use this project for credential attacks, denial of service, persistence, stealth, malware, data dumping, or testing outside approved scope.

No scanner can prove a target has no vulnerabilities. Treat a clean report as "no issues found by these checks" and review the coverage matrix plus skipped checks.

## Development

```bash
npm test
node scripts/security-audit.mjs --help
node scripts/security-audit.mjs --target . --mode passive --no-tools --json --out self-audit.json
```

Before publishing releases, check [docs/release-checklist.md](docs/release-checklist.md).

## Good First Uses

- Audit your local web app before shipping.
- Check staging headers and TLS posture.
- Generate an OWASP-mapped report for a client or internal review.
- Give an AI agent a consistent security-audit command instead of ad hoc prompts.
- Compare scanner output with manual validation and reduce false positives.

## License

MIT. See [LICENSE](LICENSE).
