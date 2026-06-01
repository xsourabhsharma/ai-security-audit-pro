# AI Security Audit Pro

![CI](https://github.com/xsourabhsharma/ai-security-audit-pro/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)
![OWASP](https://img.shields.io/badge/OWASP-ASVS%20%7C%20Top%2010%20%7C%20WSTG-111827.svg)
![Agent Ready](https://img.shields.io/badge/AI--agent--ready-Codex%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Hermes%20%7C%20OpenClaw-0f766e.svg)

AI Security Audit Pro is a universal, agent-ready security audit toolkit for web apps, APIs, and local codebases.

It gives AI agents a reliable way to run defensive security audits, collect evidence, reduce false positives, and generate professional reports. It works with Codex, Claude Code, Gemini CLI, Google Antigravity, OpenCode, Hermes, OpenClaw, and any other AI tool that can read files and run shell commands.

## Why Agents Use Commands Here

Different AI tools have different plugin systems. Codex plugins, Claude Code plugins, Gemini instructions, OpenCode agents, Hermes tools, and OpenClaw workflows do not all load the same package format.

The command line is the common interface they all understand.

That is why this project includes commands such as:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md
```

Those commands are not only for humans. They are the stable API for AI agents. An agent can call the CLI, read the generated Markdown/HTML/JSON/PDF report, validate findings, and explain the results in chat.

This means the project is not locked to one AI app or marketplace.

## What It Does

- Audits local source code for high-signal security patterns.
- Checks websites and APIs for headers, TLS, CORS, cookies, methods, exposed paths, and API documentation leaks.
- Finds secret-like values while redacting evidence.
- Runs dependency and lockfile checks when ecosystem tools are available.
- Orchestrates optional scanners such as Semgrep, OSV-Scanner, Gitleaks, TruffleHog, httpx, katana, ffuf, Nuclei, SSLyze, and OWASP ZAP.
- Produces professional Markdown, HTML, PDF, or JSON reports.
- Maps findings to OWASP Top 10, OWASP API Security Top 10, ASVS, WSTG, and CWE where practical.
- Separates confirmed findings, likely findings, needs-validation findings, skipped checks, and residual risk.
- Gives agents a repeatable security workflow instead of random ad hoc prompts.

## Best Use Cases

- Ask an AI agent to audit a local web project before release.
- Ask an agent to review an authorized staging or production website.
- Generate a client-ready or internal security report.
- Give Codex, Claude Code, Gemini CLI, OpenCode, Hermes, or OpenClaw the same audit workflow.
- Run safer AI-assisted OWASP checks with clear scope and authorization.
- Convert noisy scanner output into a professional bug-analysis report.

## Supported AI Agents And Tools

| AI agent or tool | Support path |
|---|---|
| Codex | `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `AGENTS.md` |
| Claude Code | `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` plus the universal CLI |
| Google Antigravity | `GEMINI.md` or `agent-adapters/antigravity.md` |
| OpenCode | `AGENTS.md` or `agent-adapters/opencode.md` |
| Hermes | `agent-adapters/hermes.md` plus the universal CLI as a local command tool |
| OpenClaw | `agent-adapters/openclaw.md` plus the universal CLI |
| Any other AI agent | Use the universal CLI command and the prompt below |

Universal agent prompt:

```text
Use AI Security Audit Pro from this repository. Run node scripts/security-audit.mjs against the exact target. Keep the work defensive, authorized, and non-destructive. Redact secrets. Separate confirmed findings from likely or needs-validation findings. Produce Markdown plus HTML when requested, and explain skipped checks or residual risk.
```

## Quick Start

Requirements:

- Node.js 18 or newer.
- Optional: Python plus ReportLab for PDF output.
- Optional scanners on PATH for deeper coverage: Semgrep, OSV-Scanner, Gitleaks, TruffleHog, httpx, katana, ffuf, Nuclei, SSLyze, OWASP ZAP, Docker.

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

## Universal CLI Examples For Agents

These examples are the agent-callable interface. Any AI tool with terminal access can run them.

Local project audit:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

Authorized website audit:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

Deeper authorized active scan:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

Machine-readable JSON for agents:

```bash
node scripts/security-audit.mjs --target . --json --out report.json
```

Why JSON matters: agents can parse `report.json`, rank findings, compare runs, summarize only confirmed issues, or feed results into another workflow.

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

## Report Quality

Reports are built for real review, not just raw scanner output.

Each report can include:

- Assessment conclusion.
- Finding overview.
- Key risk summary.
- Scope and authorization.
- Authenticated and business-logic scope.
- Critical, high, medium, low, and info findings.
- Evidence, risk, impact, remediation, OWASP/CWE mapping, confidence, and safe validation steps.
- Reviewed surfaces.
- Coverage matrix.
- Tool execution details.
- Skipped checks and residual risk.

## Optional Scanner Tooling

This repository intentionally does not commit large scanner binaries. Install tools separately and keep them on PATH, or set `SECURITY_AUDIT_TOOLS_DIR`.

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

## Safety And Responsible Use

Use this only on systems you own or are explicitly authorized to test.

Do not use this project for credential attacks, denial of service, persistence, stealth, malware, data dumping, or testing outside approved scope.

No scanner or AI agent can prove a target has no vulnerabilities. Treat a clean report as "no issues found by these checks" and review the coverage matrix plus skipped checks.

## Development

```bash
npm test
node scripts/security-audit.mjs --help
node scripts/security-audit.mjs --target . --mode passive --no-tools --json --out self-audit.json
```

Before publishing releases, check [docs/release-checklist.md](docs/release-checklist.md).

## License

MIT. See [LICENSE](LICENSE).
