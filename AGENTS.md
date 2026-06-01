# Agent Instructions

Security Audit Pro is a defensive security audit toolkit. Use it when the user asks to find bugs, security vulnerabilities, OWASP issues, exposed secrets, dependency vulnerabilities, weak headers, API risks, or website weaknesses.

## Core Workflow

1. Confirm scope and authorization before active testing of hosted or third-party targets.
2. Prefer local source, configs, lockfiles, and logs before live probing.
3. Run the CLI from this repository root:

```powershell
node scripts/security-audit.mjs --target <path-or-url> --mode passive --out security-audit-report.md
```

4. For authorized URL targets, use:

```powershell
node scripts/security-audit.mjs --target <url> --mode standard --authorized --out report.md --html-out report.html
```

5. For authorized deep non-destructive scans, use:

```powershell
node scripts/security-audit.mjs --target <url> --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

## Boundaries

- Never print secrets. Redact tokens, cookies, API keys, passwords, and private configuration.
- Do not run destructive exploits, credential attacks, denial of service, persistence, stealth, or data dumping.
- Mark scanner-only or client-side-only claims as `Needs validation` until server-side behavior is confirmed.
- Always report skipped checks and residual risk.

## Report Standard

Lead with confirmed high-impact findings. Every finding should include severity, status, affected surface, evidence, risk, impact, OWASP/CWE mapping when applicable, remediation, and safe validation steps.
