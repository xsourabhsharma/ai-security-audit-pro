# Changelog

## 0.8.5

- Added `--report-depth standard|deep`, with `--profile deep` automatically selecting deep report depth.
- Added reference-style deep report sections inspired by long-form manual security reviews: component inventory, reconstructed review flow, security invariants, trust assumptions, boundary conditions, exploitability narrative, evidence index, surface index, final assessment, and prioritized remediation/audit tasks.
- Added matching printable HTML deep-report pages so Markdown and HTML outputs carry the same long-form analysis.
- Extended the CLI self-test to verify deep report sections are generated.
- Bumped package and plugin manifests to `0.8.5`.

## 0.8.4

- Redesigned generated HTML reports into a printable report-document format instead of a website-style dashboard.
- Added a report cover band, executive snapshot, severity cards, findings-at-a-glance table, severity distribution visual, safe validation panel, and friendly defensive report note.
- Added a Markdown report snapshot table with overall assessment, severity totals, validation status totals, authorization status, and report ID.
- Renamed generated report title from generic bug analysis wording to `AI Security Audit Pro Report`.
- Bumped package and plugin manifests to `0.8.4`.

## 0.8.3

- Updated README release status now that `0.8.2` is live on npm and ClawHub.
- Documented the ClawHub install command and package inspection command.
- Clarified that ClawHub releases may temporarily show `scan: pending` during automated checks and indexing.
- Bumped package and plugin manifests to `0.8.3` for the next GitHub, npm, and ClawHub release.

## 0.8.2

- Added local IDOR/BOLA route hotspot detection for object lookups without nearby authorization controls.
- Added mass-assignment and privilege-field assignment review signals for API handlers.
- Added JWT/session checks for decode-without-verify, ignored expiration, weak literal secrets, weak cookie options, and browser-readable token storage.
- Added public frontend config exposure checks for sensitive-looking `NEXT_PUBLIC`, `VITE`, `REACT_APP`, and `PUBLIC` variables.
- Added GraphQL introspection/schema signals for local code and public SPA bundles.
- Added GitHub Actions CI/CD security checks for risky `pull_request_target`, write-all permissions, untrusted PR input, and floating action refs.
- Added SPA bundle checks for browser token storage and secret-like public config names with value redaction.
- Added a CLI self-test fixture so release tests prove the new checks fire.
- Bumped package and plugin manifests to `0.8.2`.

## 0.8.1

- Added SPA identity-workflow signal detection for Aadhaar/DigiLocker-style login flows where public client code sends candidate and identity fields together but cannot prove server-side binding.
- Added confirmed detection for hardcoded mobile/contact placeholders in identity login flows.
- Added payment return URL host-mismatch detection for public SPA payment configuration.
- Fixed a JavaScript bundle reporting fallback that referenced an undefined asset variable.
- Updated plugin manifests so Codex, Claude, and OpenClaw adapters advertise the current package version.
- Improved validation wording so auth-bypass claims require controlled test identities, server logs, or staging proof before being treated as confirmed.

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
