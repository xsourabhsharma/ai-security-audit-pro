# Authenticated Security Audit Scope

Use this template when the audit needs real accounts, source code, role checks, or business workflow testing. Do not paste production secrets into chat. Use dedicated test accounts and rotate or delete them after testing.

## Target

- Primary URL:
- Additional in-scope domains, subdomains, APIs, or localhost ports:
- Out-of-scope domains, paths, tenants, or third-party services:
- Preferred test window and timezone:
- Maximum request rate or concurrency:
- Allowed scan depth:

## Authorization

- Owner or authorizing organization:
- Authorization contact:
- Exact authorized activities:
- Prohibited activities:
- Data handling rules:
- Reporting deadline:

## Test Accounts

Provide dedicated test accounts for each role. Share passwords through a secure channel, local password manager, or temporary credential file outside the report.

- Anonymous user allowed: yes/no
- Role 1 name:
- Role 1 username/email:
- Role 1 expected permissions:
- Role 2 name:
- Role 2 username/email:
- Role 2 expected permissions:
- Admin or privileged role username/email:
- MFA, SSO, CAPTCHA, IP allowlist, or VPN requirements:
- Logout/session timeout behavior to expect:

## Business Workflows

List workflows that must be tested for authorization, state changes, abuse cases, and broken business logic.

- Registration/login/password reset:
- Profile or account settings:
- User-to-user object access:
- Payments, credits, subscriptions, refunds, or orders:
- File upload/download/import/export:
- Admin or staff actions:
- Notifications, email, webhooks, or callbacks:
- Rate limits or quota-sensitive flows:

## Source Code And APIs

- Local source path or repository:
- Branch/commit to scan:
- Build/test commands:
- Environment or config files available without secrets:
- API specs: OpenAPI, GraphQL schema, Postman collection:
- Known sensitive models or objects:
- Previous security reports or known accepted risks:

## Report Output

- Markdown report path:
- HTML report path:
- PDF report path:
- Severity policy or compliance mapping:
- Evidence restrictions:
