# AI Security Audit Pro Plugin

![CI](https://github.com/xsourabhsharma/ai-security-audit-pro/actions/workflows/ci.yml/badge.svg)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)
![OWASP](https://img.shields.io/badge/OWASP-ASVS%20%7C%20Top%2010%20%7C%20WSTG-111827.svg)
![Plugin Ready](https://img.shields.io/badge/plugin--ready-Codex%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Hermes%20%7C%20OpenClaw-0f766e.svg)

**A powerful universal security-audit plugin for AI agents.**

AI Security Audit Pro Plugin gives Codex, Claude Code, Gemini CLI, Google Antigravity, OpenCode, Hermes, OpenClaw, and any shell-capable AI tool a shared defensive security-audit workflow for codebases, websites, and APIs.

It is a plugin package plus a universal CLI engine. Native plugin metadata is included where agent platforms support it, and every other AI agent can use the same audit engine through terminal commands.

## Why This Is A Plugin And A CLI

AI tools do not all share one plugin format.

Codex uses Codex plugin metadata. Claude Code uses Claude plugin metadata. Gemini CLI and Antigravity use instruction files. OpenCode, Hermes, OpenClaw, and other tools often integrate best through local command tools.

So this project ships both:

- **Plugin instructions and manifests** for AI tools that understand plugin-style packages.
- **A universal Node.js audit engine** that every agent can call through the shell.

The CLI commands are the stable runtime interface of the plugin. They let any AI agent run the same audit workflow, read the generated reports, validate findings, and explain results in chat.

## What Makes It Powerful

- **Multi-agent support:** Codex, Claude Code, Gemini CLI, Antigravity, OpenCode, Hermes, OpenClaw, and generic shell-capable agents.
- **Multi-surface coverage:** local source code, dependency files, exposed secrets, web headers, TLS, cookies, CORS, HTTP methods, public paths, API docs, crawled URLs, and authorized DAST output.
- **Professional reporting:** Markdown, HTML dashboard, PDF, and JSON outputs.
- **OWASP alignment:** OWASP Top 10, OWASP API Security Top 10, ASVS, WSTG, and CWE where practical.
- **Scanner orchestration:** integrates with Semgrep, OSV-Scanner, Gitleaks, TruffleHog, httpx, katana, ffuf, Nuclei, SSLyze, OWASP ZAP, and ecosystem audit tools when installed.
- **Agent-friendly JSON:** lets AI systems parse findings, compare scans, rank severity, and produce summaries.
- **False-positive discipline:** separates confirmed findings, likely findings, needs-validation findings, skipped checks, and residual risk.
- **Business-logic scope support:** includes an authenticated audit scope template for role testing, object authorization, uploads, quotas, admin workflows, and API review.

## What It Helps Find

- Missing or weak security headers.
- Weak TLS posture.
- Risky CORS behavior.
- Publicly exposed sensitive files or debug endpoints.
- API documentation exposure.
- Secret-like values in source code.
- Vulnerable dependencies when ecosystem tools are available.
- Injection and unsafe execution hotspots.
- XSS sinks and unsafe HTML rendering.
- SSRF and outbound request hotspots.
- File-read and path traversal review points.
- Unsafe deserialization patterns.
- Authorization and business-logic review hotspots.

No security tool can honestly guarantee it finds every vulnerability. This plugin is built to find high-signal issues quickly, produce evidence, and show what still needs manual validation.

## Supported AI Agents And Tools

| Agent or tool | Plugin support |
|---|---|
| Codex | `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `AGENTS.md` |
| Claude Code | `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` plus the universal CLI engine |
| Google Antigravity | `GEMINI.md` or `agent-adapters/antigravity.md` |
| OpenCode | `AGENTS.md` or `agent-adapters/opencode.md` |
| Hermes | `agent-adapters/hermes.md` plus the CLI as a local command tool |
| OpenClaw | `agent-adapters/openclaw.md` plus the universal CLI engine |
| Any other AI agent | Use the universal prompt and CLI command interface |

Universal prompt for any AI agent:

```text
Use AI Security Audit Pro Plugin from this repository. Run node scripts/security-audit.mjs against the exact target. Keep the audit defensive, authorized, and non-destructive. Redact secrets. Separate confirmed findings from likely or needs-validation findings. Produce Markdown plus HTML when requested, and explain skipped checks or residual risk.
```

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
- Optional scanners on PATH for deeper coverage.

## Agent-Callable Audit Commands

These commands are intentionally simple because AI agents can call them reliably.

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

Machine-readable JSON for AI workflows:

```bash
node scripts/security-audit.mjs --target . --json --out report.json
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

## Report Quality

Reports are written for real security review, not just raw scanner dumping.

Reports can include:

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

The plugin still works without these tools and records skipped external checks in the report.

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

A clean report means "no issues found by these checks." It does not prove the target has no vulnerabilities. Review the coverage matrix, skipped checks, and manual validation notes.

## Development

```bash
npm test
node scripts/security-audit.mjs --help
node scripts/security-audit.mjs --target . --mode passive --no-tools --json --out self-audit.json
```

Before publishing releases, check [docs/release-checklist.md](docs/release-checklist.md).

## License

MIT. See [LICENSE](LICENSE).
