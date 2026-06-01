# Claude Code Instructions

Use the `security-audit` skill in `skills/security-audit/SKILL.md` for defensive security review tasks.

When a user asks for a website or project security audit:

1. Identify the exact target.
2. Confirm authorization before active testing of hosted targets.
3. Run `node scripts/security-audit.mjs` from this repository root.
4. Triage output manually. Do not treat raw scanner output as confirmed exploitability.
5. Produce a concise, evidence-based report.

For local code:

```bash
node scripts/security-audit.mjs --target . --out security-audit-report.md
```

For an authorized website:

```bash
node scripts/security-audit.mjs --target https://staging.example.com --mode active --profile deep --authorized --out report.md --html-out report.html
```

Do not expose secrets or run destructive testing.
