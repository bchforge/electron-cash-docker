# Security Policy

Electron Cash Docker is self-hosted wallet software. A vulnerability in the
image, Compose configuration, plugin packaging, or documentation can put wallet
data or operator systems at risk. Do not disclose a suspected vulnerability in
a public issue before the maintainer has had an opportunity to assess it.

## Private Reporting

Use GitHub's **Report a vulnerability** button in the repository's Security tab.
This creates a private vulnerability report visible to the repository
maintainers and GitHub security tooling. If the button is unavailable, contact a
repository maintainer through an existing private GitHub channel and do not
include secrets in a public issue.

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
