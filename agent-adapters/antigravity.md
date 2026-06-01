# Google Antigravity Adapter

Use the instructions in `GEMINI.md` and call the CLI from the repository root.

Local project:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md
```

Authorized website:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode standard --authorized --out report.md --html-out report.html
```

Keep testing defensive, scoped, and non-destructive.
