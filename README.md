# AI Security Audit Pro Plugin

> A security-audit plugin that AI agents can actually run.

![CI](https://github.com/xsourabhsharma/ai-security-audit-pro/actions/workflows/ci.yml/badge.svg)
[![npm](https://img.shields.io/npm/v/ai-security-audit-pro.svg)](https://www.npmjs.com/package/ai-security-audit-pro)
[![ClawHub](https://img.shields.io/badge/ClawHub-ai--security--audit--pro-111827.svg)](https://clawhub.ai/plugins/ai-security-audit-pro)
![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![Node.js](https://img.shields.io/badge/node-%3E%3D18-339933.svg)
![OWASP](https://img.shields.io/badge/OWASP-ASVS%20%7C%20Top%2010%20%7C%20WSTG-111827.svg)
![Plugin Ready](https://img.shields.io/badge/plugin--ready-Codex%20%7C%20Claude%20%7C%20Gemini%20%7C%20OpenCode%20%7C%20Hermes%20%7C%20OpenClaw-0f766e.svg)

AI Security Audit Pro Plugin is a defensive security-audit plugin and CLI engine for AI coding agents. It gives Codex, Claude Code, Gemini CLI, Google Antigravity, OpenCode, Hermes, OpenClaw, and other shell-capable AI tools a serious workflow for auditing codebases, websites, and APIs.

It is built for people who want their agent to do more than produce generic advice. A good run should inspect the target, use the right tools, capture evidence, separate real findings from scanner noise, and produce a report someone can actually review.

## The Idea

AI agents are useful at security work, but only when they have a disciplined process.

Without structure, they tend to:

- repeat the same low-value header findings,
- overstate scanner output,
- miss scope and authorization details,
- mix real findings with guesses,
- and produce reports that are hard to trust.

This plugin gives the agent a safer, repeatable path:

1. Understand the target.
2. Run local or URL-based audit checks.
3. Use optional scanners when they are installed and authorized.
4. Write down what was reviewed and what was skipped.
5. Mark findings as `Confirmed`, `Likely`, or `Needs validation`.
6. Generate Markdown, HTML, PDF, or JSON output.

That is the point of this repo: not just "run a scanner," but help an AI agent behave more like a careful security reviewer.

## Plugin First, CLI Powered

Every AI tool has a different plugin system. Codex, Claude Code, Gemini CLI, Antigravity, OpenCode, Hermes, and OpenClaw do not all load the same package format.

So AI Security Audit Pro ships as both:

| Part | What it does |
|---|---|
| Plugin files | Give agents the instructions, skills, and adapter docs they need. |
| CLI engine | Gives every shell-capable agent one stable way to run the audit. |

The CLI is the runtime interface of the plugin:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

An agent can run that command, read the report, validate the evidence, summarize the risk, and tell you what still needs manual testing.

## Download And Install

The package is published on npm:

- npm package: [ai-security-audit-pro](https://www.npmjs.com/package/ai-security-audit-pro)
- GitHub source: [xsourabhsharma/ai-security-audit-pro](https://github.com/xsourabhsharma/ai-security-audit-pro)

Install it globally when you want the CLI available to Codex, Claude Code, Gemini CLI, OpenCode, Hermes, OpenClaw, or any other shell-capable agent:

```bash
npm install -g ai-security-audit-pro
security-audit-pro --target . --out security-audit-report.md --html-out security-audit-report.html
```

ClawHub support is packaged through `openclaw.plugin.json`, but the ClawHub listing is pending registry approval/publish. After it is visible on ClawHub, OpenClaw users will be able to install it with:

```bash
openclaw plugins install clawhub:ai-security-audit-pro
```

## Supported Agents

| Agent or tool | Included support |
|---|---|
| Codex | `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `AGENTS.md` |
| Claude Code | `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, `CLAUDE.md` |
| Gemini CLI | `GEMINI.md` and the CLI workflow |
| Google Antigravity | `GEMINI.md` or `agent-adapters/antigravity.md` |
| OpenCode | `AGENTS.md` or `agent-adapters/opencode.md` |
| Hermes | `agent-adapters/hermes.md` and the CLI as a local command tool |
| OpenClaw | `agent-adapters/openclaw.md` and the CLI workflow |
| Any other AI agent | Use the universal prompt and CLI command |

Universal prompt:

```text
Use AI Security Audit Pro Plugin from this repository. Run node scripts/security-audit.mjs against the exact target. Keep the audit defensive, authorized, and non-destructive. Redact secrets. Separate confirmed findings from likely or needs-validation findings. Produce Markdown plus HTML when requested, and explain skipped checks or residual risk.
```

## What It Can Check

| Surface | Examples |
|---|---|
| Source code | Injection hotspots, unsafe execution, XSS sinks, SSRF hotspots, file access, deserialization, XML parser risks, auth review hotspots. |
| Secrets | API keys, tokens, private keys, JWTs, cloud keys, and secret-like assignments with redacted evidence. |
| Dependencies | npm, pnpm, yarn, pip-audit, Bandit, OSV-Scanner, govulncheck, cargo-audit, composer audit when available. |
| Websites | Headers, TLS, cookies, CORS, HTTP methods, exposed files, debug endpoints, API docs, security.txt. |
| APIs | OpenAPI, Swagger, GraphQL, Postman artifacts, route inventory, authorization hotspots. |
| Active scanning | Authorized httpx, SSLyze, katana, ffuf, Nuclei, and OWASP ZAP orchestration when installed. |
| Business logic | Role testing, object authorization, uploads, quotas, sharing, admin flows, and workflow-abuse planning through the scope template. |
| Reports | Markdown, HTML dashboard, PDF, and JSON. |

## What Makes It Useful

- It is agent-neutral. The same repo can guide Codex, Claude Code, Gemini CLI, OpenCode, Hermes, OpenClaw, and other tools.
- It gives agents a real command to run instead of relying on vague prompt memory.
- It records skipped checks instead of pretending coverage happened.
- It encourages validation instead of treating every scanner result as a confirmed bug.
- It produces reports with impact, evidence, remediation, OWASP/CWE mapping, and safe validation steps.
- It can be used on local projects, localhost apps, staging sites, and authorized public targets.
- It supports JSON output so agents can parse results and build follow-up workflows.

No honest security tool can promise to find every vulnerability. This plugin is designed to find strong signals, preserve evidence, and make the remaining gaps visible.

## Quick Start

Fastest path from npm:

```bash
npm install -g ai-security-audit-pro
security-audit-pro --target . --out security-audit-report.md --html-out security-audit-report.html
```

Source checkout path:

```bash
git clone https://github.com/xsourabhsharma/ai-security-audit-pro.git
cd ai-security-audit-pro
npm test
```

Run the local engine from source:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

OpenClaw path, once the ClawHub listing is live:

```bash
openclaw plugins install clawhub:ai-security-audit-pro
```

Requirements:

- Node.js 18 or newer.
- Optional: Python plus ReportLab for PDF output.
- Optional scanner tools on PATH for deeper coverage.

## Common Audit Commands

Local project:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md --html-out security-audit-report.html
```

Authorized website:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

Deep authorized active scan:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

JSON for agent workflows:

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

- `safe`: lower request volume.
- `balanced`: default profile.
- `deep`: broader non-destructive coverage for explicitly authorized targets.

## What A Report Looks Like

The output is meant to read like a real security handoff, not a raw tool dump.

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

Each finding can include:

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

When a tool is missing, the report says so clearly.

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
