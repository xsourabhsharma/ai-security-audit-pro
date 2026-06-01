# Authenticated Security Audit Scope Example

## Target

- Primary URL: https://staging.example.com
- Additional in-scope domains, subdomains, APIs, or localhost ports: https://api.staging.example.com
- Out-of-scope domains, paths, tenants, or third-party services: payment provider, production tenant
- Preferred test window and timezone: 10:00-16:00 UTC
- Maximum request rate or concurrency: 2 concurrent requests
- Allowed scan depth: non-destructive active scanning, no destructive workflows

## Authorization

- Owner or authorizing organization: Example Inc.
- Authorization contact: security@example.com
- Exact authorized activities: headers, TLS, CORS, crawler discovery, authenticated role checks, upload validation with safe test files
- Prohibited activities: credential attacks, denial of service, production data extraction
- Data handling rules: redact user data and secrets
- Reporting deadline: 7 days after test

## Test Accounts

- Anonymous user allowed: yes
- Role 1 name: regular user
- Role 1 username/email: user-a@example.com
- Role 1 expected permissions: manage own profile and own objects
- Role 2 name: regular user
- Role 2 username/email: user-b@example.com
- Role 2 expected permissions: manage own profile and own objects
- Admin or privileged role username/email: not provided
- MFA, SSO, CAPTCHA, IP allowlist, or VPN requirements: none
- Logout/session timeout behavior to expect: 24 hours

## Business Workflows

- Registration/login/password reset: yes
- Profile or account settings: yes
- User-to-user object access: yes
- Payments, credits, subscriptions, refunds, or orders: no
- File upload/download/import/export: yes
- Admin or staff actions: no
- Notifications, email, webhooks, or callbacks: no
- Rate limits or quota-sensitive flows: yes
