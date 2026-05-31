# Security Policy

Steward handles authentication, wallets, policy enforcement, and credential
proxying. Please do not open public issues for suspected vulnerabilities.

## Reporting

Email security reports to `contact@nubscarson.com` with:

- a short summary,
- affected package or endpoint,
- reproduction steps,
- expected impact,
- any logs or screenshots with secrets redacted.

Use environment variable names in reports instead of secret values.

## Scope

In scope:

- authentication bypass,
- wallet or signing policy bypass,
- private key or API credential exposure,
- tenant isolation failures,
- privilege escalation,
- unauthenticated access to protected agent or proxy operations.

Out of scope:

- spam or social engineering,
- denial-of-service without a practical exploit path,
- findings that require leaked credentials already outside the system.

## Handling

I will acknowledge credible reports as quickly as possible and coordinate a
private fix before public disclosure.
