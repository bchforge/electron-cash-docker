# Security Policy

Electron Cash Docker is self-hosted wallet software. A vulnerability in the
image, Compose configuration, plugin packaging, or documentation can put wallet
data or operator systems at risk. Do not disclose a suspected vulnerability in
a public issue before the maintainer has had an opportunity to assess it.

## Private Reporting

Use the repository's private GitLab vulnerability-reporting or maintainer
contact channel when available. If that channel is unavailable, contact a
repository maintainer privately before opening a public issue. Do not include
secrets in a public issue.

Please include:

- the affected release, commit, image, or configuration;
- a concise description and security impact;
- reproducible steps or a minimal proof of concept;
- relevant logs with credentials, wallet data, and private keys removed; and
- any suggested mitigation or disclosure constraints.

Do not send recovery seeds, wallet passwords, RPC passwords, private keys, or
production configuration in a report.

## Supported Versions

The latest published release and the default branch are the supported lines for
security fixes. Older tags should be upgraded before investigating a report.
Security fixes are maintainer-run project work; CI and dependency scans are not
an independent security audit or a guarantee that every upstream or host-level
vulnerability has been found.

## Automated Validation

The accepted v0.2.1 candidate validation on 2026-09-15 used Bandit `1.9.4` and
Trivy `0.74.0`. Bandit reported zero findings under the gate's blocking
high-severity/high-confidence policy. Trivy reported zero fixable HIGH or
CRITICAL vulnerabilities across the source and freshly built wallet/Tor image
scans, while its source secret scan reported zero findings.

The retained no-fix HIGH finding is `CVE-2024-23342` in `ecdsa==0.19.1`.
It remains visible in machine-readable evidence and is allowed only by the
active, review-dated exception for the documented source and Electron Cash image
scopes. This exception is not a claim that the package advisory is fixed; see
[`docs/ci-security.md`](docs/ci-security.md) for the mitigation and review
policy.
