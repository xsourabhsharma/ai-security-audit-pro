# OpenCode Adapter

Use Security Audit Pro for defensive security audits.

Command:

```bash
node scripts/security-audit.mjs --target <target> --out security-audit-report.md
```

For authorized web targets:

```bash
node scripts/security-audit.mjs --target <url> --mode active --profile deep --authorized --out report.md --html-out report.html
```

Rules:

- Confirm exact target and authorization before active testing.
- Redact secrets.
- Do not run destructive testing or credential attacks.
- Separate confirmed findings from likely or needs-validation findings.
