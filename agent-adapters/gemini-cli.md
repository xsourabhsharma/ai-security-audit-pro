# Gemini CLI Adapter

Gemini CLI can use `GEMINI.md` as its instruction file and call:

```bash
node scripts/security-audit.mjs --target <target> --out security-audit-report.md
```

For authorized websites:

```bash
node scripts/security-audit.mjs --target <url> --mode standard --authorized --out report.md --html-out report.html
```
