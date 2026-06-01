# Safety Model

Security Audit Pro is for defensive assessment of systems you own or are explicitly authorized to test.

## Allowed By Design

- Local source review.
- Secret scanning with redacted output.
- Dependency and lockfile checks.
- HTTP headers, TLS, cookie, CORS, and method checks.
- Bounded crawler and content discovery on authorized targets.
- Safe proof and validation steps that do not change data or degrade service.

## Requires Explicit Authorization

- Active scanning against any hosted target.
- Authenticated role testing.
- Business-logic testing.
- API object authorization testing.
- Upload, import, export, deletion, sharing, payment, quota, and admin workflows.

## Out Of Scope

- Credential attacks.
- Denial of service.
- Persistence.
- Stealth.
- Data dumping.
- Malware.
- Bypassing MFA or CAPTCHA.
- Testing outside the authorized target scope.

## Reporting Rule

Every report must separate:

- Confirmed findings.
- Likely findings.
- Needs-validation findings.
- False positives.
- Skipped checks.
- Residual risk.

No automated scanner can prove that a target has no vulnerabilities.
