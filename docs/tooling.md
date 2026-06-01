# Optional Tooling

The CLI works with Node.js alone, but it can orchestrate additional tools when they are installed.

## Local Project Tools

- Semgrep
- OSV-Scanner
- Gitleaks
- TruffleHog
- npm, pnpm, yarn audit
- pip-audit
- Bandit
- govulncheck
- cargo-audit
- composer audit

## Website Tools

- httpx
- katana
- ffuf
- Nuclei
- SSLyze
- OWASP ZAP
- Docker for ZAP Docker baseline

## Tool Discovery

Security Audit Pro looks in:

- PATH
- `SECURITY_AUDIT_TOOLS_DIR`
- `./tools`
- `./tools/bin`
- `./tools/nuclei`
- User install paths such as `~/go/bin` and `~/.local/bin`

Do not commit downloaded scanner binaries into this repository.
