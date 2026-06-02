# Changelog

## 0.8.0

- Added a dedicated `Confirmed Vulnerabilities / Risks` report section for clearer executive-style handoffs.
- Added HTTP-to-HTTPS redirect enforcement checks for URL targets.
- Added duplicate/conflicting security header detection on adjacent API endpoints.
- Added XSRF cookie hardening checks for `SameSite` and insecure HTTP cookie behavior.
- Added `security.txt` availability checks for responsible disclosure readiness.
- Added recursive SPA JavaScript bundle analysis for lazy-loaded chunks.
- Added public bundle risk signals for production debug logging, sensitive endpoint maps, and client-side password transforms.
- Improved safe validation guidance for HTTP redirect findings.

## 0.7.0

- Added professional Markdown, HTML, and PDF report outputs.
- Added coverage matrix, reviewed surfaces, skipped checks, and residual-risk sections.
- Added authorized active scan orchestration for common external tools when installed.
- Added authenticated/business-logic scope template.
- Added GitHub-ready metadata and cross-agent instruction files.
