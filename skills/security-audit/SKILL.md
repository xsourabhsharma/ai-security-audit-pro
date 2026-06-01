---
name: security-audit
description: Defensive web and web-application security auditing for local projects, localhost, staging, and authorized public/private websites. Use when the user asks to audit, scan, review, find vulnerabilities, check OWASP issues, inspect security headers, assess APIs, or produce a security report for a website or web app.
---

# Security Audit Pro

Use this skill for defensive security audits only. The user must own the target or have explicit authorization before any active probing, crawler-based DAST, fuzzing, brute-force simulation, or scanner that sends vulnerability payloads.

## Core Rule

Be powerful, but evidence-driven and non-destructive:

- Prefer local source, configs, lockfiles, logs, and official docs over guessing.
- Run passive/local checks first.
- Ask before active DAST on a public or third-party target unless the user already gave explicit authorization for that exact target.
- Never print secrets. If a secret-like value is found, report only file, line, type, and a short redacted prefix/suffix.
- Do not exploit, persist access, bypass auth, dump data, run credential attacks, or cause service degradation.

## Audit Levels

- `passive`: local code checks plus one fetch of the supplied URL. Safe default.
- `standard`: passive checks plus shallow common-exposure checks on authorized targets. The runner requires `--authorized` for URL targets.
- `active`: runs installed active scanners such as Nuclei or OWASP ZAP where authorized. The runner requires `--authorized` for URL targets.
- Diff scope: local project mode can add `--diff-base <ref>` to focus source scans on changed files from a Git baseline.

If the user says "everything", start with `passive` and `standard` where authorization is clear, then explain what would need explicit confirmation for `active`.

## Baselines To Apply

Use these frameworks when triaging and reporting:

- OWASP Top 10:2021 for application risk categories.
- OWASP API Security Top 10:2023 for API-specific risk.
- OWASP ASVS 5.0.0 for verification requirements.
- OWASP WSTG for test coverage.
- OWASP Cheat Sheet Series and Secure Headers Project for remediation.
- CWE IDs when a finding maps cleanly.

## Workflow

1. Scope
   - Identify whether the target is a local project path, localhost URL, staging URL, production URL, API spec, or mixed scope.
   - Check for app stack, package manager, lockfiles, framework, API routes, auth/session code, and deployment config.
   - Confirm authorization before active testing if the target is public or third-party.

2. Run the local runner
   - From the workspace root:

```powershell
node scripts/security-audit.mjs --target <path-or-url> --mode passive --out security-audit-report.md
```

   - Use `--mode standard --authorized` only when shallow exposure checks are appropriate and the user owns or is authorized to test the target.
   - Use `--mode active --authorized` only after explicit authorization for the exact URL.
   - Use `--profile deep` when the user explicitly asks for the fullest non-destructive authorized scan. Use `--profile safe` when rate or fragility is a concern.
   - Use `--diff-base <ref>` for Git-backed change scans.
   - Use `--scope-file <file>` when authenticated roles, business workflows, API scope, or source/live correlation is in scope.
   - Use `--html-out <file>` when the user wants a browser-readable report.
   - Use `--pdf-out <file>` when the user wants a PDF report and Python ReportLab is available.
   - Use `--json` when the user asks for machine-readable output.

3. Add specialist checks
   - For source projects, run available ecosystem checks:
     - JavaScript/TypeScript: `npm audit --json`, `pnpm audit --json`, `yarn npm audit --json`, or Semgrep when available.
     - Python: `pip-audit`, Bandit, or Semgrep when available.
     - Go: `govulncheck`.
     - Rust: `cargo audit`.
     - PHP: `composer audit`.
     - Multi-ecosystem: `osv-scanner`.
     - Secrets: built-in redacted regex scan plus `gitleaks` or `trufflehog` when installed.
   - For websites, check HTTP headers, TLS, cookie flags, CORS, mixed-content hints, sensitive file exposure, and security.txt.
   - For APIs, inspect OpenAPI/GraphQL schema if present, auth requirements, rate limits, object-level authorization, and error handling.
   - For local web apps, use the Browser plugin for visible behavior and localhost flows when UI verification matters.
   - For authorized website deep scans, active mode automatically uses the installed safe toolchain where available: HTTP method checks, CORS reflection probes, API schema discovery, httpx technology fingerprinting, SSLyze deep TLS checks on HTTPS, katana bounded crawling, ffuf high-signal content discovery, Nuclei templates, OWASP ZAP Docker baseline when Docker is running, and bundled standalone OWASP ZAP Quick Start when Docker is unavailable. Use subfinder/naabu only when subdomain or port discovery is explicitly in scope.
   - For authenticated, role-based, or business-logic testing, collect exact scope with `templates/authenticated-audit-scope.md` before running role/workflow checks.

4. Triage
   - Group findings by severity: Critical, High, Medium, Low, Info.
   - De-duplicate scanner noise.
   - Include evidence, affected file/URL, impact, exploitability in plain terms, and remediation.
   - Include safe PoC or validation steps for each finding. Use header-only requests, bounded commands, local scanner commands, or manual review instructions; do not include destructive exploit chains, credential attacks, data dumping, DoS, persistence, or stealth bypass steps.
   - Mark uncertain findings as "Needs validation" instead of overstating them.

5. Deliver
   - Lead with the highest-risk confirmed findings.
   - Include commands run, skipped checks, and why.
   - Recommend next checks only if they materially improve confidence.

## Report Shape

Use this shape for reports:

```markdown
# Bug Analysis Report for <Target>

## Assessment Conclusion

## Finding Overview

## Key Risk Summary

## Scope And Authorization

## Auth And Business Logic Scope

## Critical Severity Findings

## High Severity Findings

## Medium Severity Findings

## Low Severity Findings

## Info Severity Findings

## Reviewed Surfaces

## Coverage Matrix

## Checks Run

## Tool Execution

## Skipped Checks And Residual Risk
```

Every finding should include:

```markdown
- Status: Confirmed / Likely / Needs validation
- Severity:
- Category:
- Finding:
- Affected surface:
- Evidence:
- Risk:
- Impact:
- OWASP mapping:
- CWE:
- Confidence:
- Remediation:
- Safe PoC / validation:
- Validation needed:
```

Do not claim exploitability from client-side JavaScript or scanner output alone. Mark those as Needs validation unless server-side behavior has been directly confirmed.

## Severity Guidance

- Critical: likely account takeover, auth bypass, RCE, exposed secrets with real access, payment/PII compromise, mass data access.
- High: reliable privilege escalation, SQL/command injection, stored XSS in privileged flows, broken object authorization, sensitive production config exposure.
- Medium: reflected XSS, weak CSP, missing cookie flags, missing rate limits, known vulnerable dependency without proven exploit path.
- Low: hardening gaps, verbose headers, minor information disclosure.
- Info: inventory, tool limitations, defense-in-depth suggestions.

## Active Testing Boundary

Before running active scanners against a hosted target, state the exact target and mode and ask for confirmation if authorization is not already explicit. Safe wording:

```text
I can run active DAST against https://staging.example.com. Confirm you own or are authorized to test this target and want active scanning.
```

## Limits

No scanner can prove a website has no vulnerabilities. Treat a clean result as "no issues found by these checks." Always inspect the Coverage Matrix and Skipped Checks sections, then add authenticated testing, role-based authorization tests, business-logic review, and manual validation for high-value systems.
