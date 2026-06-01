# Release Checklist

Before releasing:

1. Run:

```bash
npm test
node scripts/security-audit.mjs --target . --mode passive --no-tools --out self-audit.md
```

2. Confirm `tools/`, `reports/`, scan outputs, secrets, and local credentials are not included.
3. Review `SECURITY.md`.
4. Choose whether to create a GitHub release tag.

Suggested first tag:

```bash
git tag v0.7.0
```
