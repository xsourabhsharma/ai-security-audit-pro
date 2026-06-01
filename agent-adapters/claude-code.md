# Claude Code Adapter

Claude Code can use `.claude-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `CLAUDE.md`.

Run:

```bash
node scripts/security-audit.mjs --target <target> --out security-audit-report.md
```

Follow the active testing and secret-redaction boundaries in `CLAUDE.md`.
