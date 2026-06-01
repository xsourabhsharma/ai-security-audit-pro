# Hermes Adapter

Register the Security Audit Pro CLI as a local command tool:

```bash
node scripts/security-audit.mjs --target <target> --out security-audit-report.md
```

Recommended behavior:

- Use passive mode first.
- Use standard or active mode only when the user provides exact authorization.
- Save Markdown and HTML reports for review.
- Do not expose secrets or private scan artifacts in chat.
