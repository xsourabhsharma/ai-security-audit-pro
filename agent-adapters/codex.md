# Codex Adapter

Codex can use `.codex-plugin/plugin.json`, `skills/security-audit/SKILL.md`, and `AGENTS.md`.

Use:

```powershell
node scripts/security-audit.mjs --target . --out security-audit-report.md
```

For authorized active website checks:

```powershell
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --out report.md --html-out report.html
```
