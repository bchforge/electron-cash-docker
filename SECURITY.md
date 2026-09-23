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

Releases are validated with Bandit static analysis and Trivy vulnerability
scanning. Trivy scans the source and container images for HIGH and CRITICAL
vulnerabilities. The current validated result is 0 fixable HIGH or CRITICAL
vulnerabilities.

The known no-fix `CVE-2024-23342` in `ecdsa==0.19.1` remains documented and
permitted under the reviewed security exception. The package advisory remains
open; this is not a claim that it is fixed. Electron Cash Docker requires the
verified BCH-specific `libsecp256k1` backend for private operations.

## v0.3 Security Controls

The web interface uses a password-only login form backed by
`auth-session`/`forward_auth` and session cookies. The form has no username
field, and no username is required.
Browser-native challenge authentication and a password-derived browser verifier
are not used as the access mechanism. WebSocket and noVNC traffic is protected
by the same authentication check as the browser assets.

The default `CADDY_EDGE_BIND=127.0.0.1` keeps the edge on loopback. Local HTTP
port 80 and HTTPS port 443 are independent endpoints; local HTTP is not
redirected to HTTPS. Local HTTPS uses Caddy's internal CA and may require
browser/OS trust setup. For a public domain, set `CADDY_SITE_ADDRESS` to the
domain only, without a scheme, set `CADDY_EDGE_BIND=0.0.0.0`, and ensure ports
80 and 443 are reachable. Caddy then provides automatic HTTP-to-HTTPS
redirects and TLS for that public site.

Fail2ban consumes structured Caddy 401 records and enforces bans in the shared
Caddy namespace using the direct client address; arbitrary forwarded headers
are not trusted. With supported proxy topologies, Caddy maintains the logical
block according to its implementation. A packet-level client DROP depends on
the topology and direct visibility of the client IP, so it is not universal
through proxies.

The POSIX backup launcher has been exercised on Linux. When an existing
host-side restore-state directory is present, its permission check uses
GNU-style `stat -c`; macOS/BSD `stat` is not a demonstrated host. Archive
processing remains inside the image. Backup/restore automatically quiesces only
the Electron Cash writer, uses an interactive passphrase with AES-256 GPG
encryption, validates the existing
manifest and hashes, snapshots the current named volume to a temporary Docker
volume, and restores that snapshot automatically if replacement or health
verification fails.
