# Gemini CLI And Antigravity Instructions

Security Audit Pro is available as a local CLI in this repository.

Use it for defensive web and application security audits:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md
```

For authorized URL checks:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

For deeper authorized non-destructive checks:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --scope-file templates/authenticated-audit-scope.md --out report.md --html-out report.html --pdf-out report.pdf
```

Rules:

- Require exact scope and authorization before active testing.
- Do not print secrets.
- Do not run destructive exploitation, credential attacks, denial of service, persistence, stealth, or data dumping.
- Treat a clean scan as "no issues found by these checks", not as proof that no vulnerabilities exist.
