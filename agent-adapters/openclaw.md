# OpenClaw Adapter

Use the universal CLI:

```bash
node scripts/security-audit.mjs --target <target>
```

Preferred report command:

```bash
node scripts/security-audit.mjs --target <target> --out report.md --html-out report.html
```

For hosted active scans, require `--authorized` and exact scope.

Never dump secrets, credentials, cookies, tokens, or private user data.
