# Contributing

Contributions should improve defensive security coverage, report quality, portability, or documentation.

## Development

```bash
npm test
node scripts/security-audit.mjs --help
```

## Rules

- Do not commit scanner binaries, reports, secrets, cookies, credentials, or private target data.
- Keep findings evidence-based and avoid overstating scanner output.
- Keep active checks bounded and non-destructive.
- Add documentation for new checks, flags, or report fields.

## Pull Requests

Include:

- What changed.
- How it was tested.
- Any new tool dependency.
- Any safety or false-positive considerations.
