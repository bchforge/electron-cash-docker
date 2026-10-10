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

Before release, `./scripts/ci.sh gate` is mandatory; `fast` is only a lightweight
regression check. Fetching official notices is not an applicability review:
`FETCHED_NOT_ASSESSED` is collection-only and never authorizes release. To renew
a review, use a fresh external directory (`$XDG_STATE_HOME/electron-cash-docker/ci/<run-id>`
or `CI_REPORT_DIR`):

```sh
python3 scripts/release_security.py fetch --report-dir "$CI_REPORT_DIR"
# Responsibly evaluate security-evaluation.pending.json; never approve by copying hashes alone.
python3 scripts/release_security.py review --report-dir "$CI_REPORT_DIR" --evaluation "$CI_REPORT_DIR/security-evaluation.pending.json"
SECURITY_ATTESTATION="$CI_REPORT_DIR/security-attestation.json" ./scripts/ci.sh gate
```

`security/upstream-reviews.json` is only the permanent catalog (19 official sources,
13 required families), independently pinned by the validator. Read the downloaded
`official-sources/*.raw` and receipts, actual immutable image inventory, complete
scanner/SBOM reports and applicability evidence before explicitly filling each
source/family decision, rationale, limitations, actual approved versions and image
IDs, reviewer and UTC review/expiry timestamps (at most seven days). The pending
template is unapproved. `review` validates a supplied evaluation; it cannot prove
the reviewer's human identity or the truth of prose. Approval requires real analysis.
Keep the evaluation and `security-attestation.json` outside Git; weekly renewal
requires no commit. A subsequent offline-approved gate still requires fresh downloads
matching every approved semantic hash, the same source candidate and actual images;
missing approval in remote CI blocks. The execution manifest hashes the approval,
downloaded evidence, inventory, scans and SBOMs; final verification checks them again.
For independently prepared real candidate images and fresh scans, `inventory
--report-dir "$CI_REPORT_DIR" --trivy <executable>` reads that run's image references
and IDs from `gate-manifest.json` and collects read-only, network-isolated probes;
it never approves. A previous gate's inventory is historical, not a new approval.
`complete --report-dir "$CI_REPORT_DIR" --trivy <executable>` and `verify --report-dir
"$CI_REPORT_DIR"` operate on that run's `gate-manifest.json`; security completion alone
does not pass the mandatory full suite. Keep exceptions exact,
justified, owned, and time-bounded in `security/vulnerability-exceptions.json`;
assess changed sources before renewing external approval. An unavailable required
source, incomplete/stale/unassessed coverage, an unevaluated vulnerability or
invalid exception, or an omitted/failed mandatory suite prevents PASS.

The canonical gate downloads sources before building, then exposes
`component-inventory.json` and `security-review-ready.json` after actual-image
scans. It requires an explicit external `SECURITY_ATTESTATION` before runtime
acceptance. `CI_SECURITY_REVIEW_WAIT_SECONDS` optionally allows a bounded
0–3600 second wait for that file (default 0); it never evaluates or approves
sources. An autonomous technical evaluator must identify itself and its limits,
without claiming human approval. The evaluated preflight refreshes official
sources again and rejects changed evidence before security completion.

Releases are validated with Bandit static analysis and Trivy vulnerability
scanning. Trivy scans the source and container images for HIGH and CRITICAL
vulnerabilities. Results are candidate-specific in the canonical gate manifest;
an older passing badge or report does not validate an uncommitted candidate.

Applicable vulnerability exceptions are recorded in
[`security/vulnerability-exceptions.json`](security/vulnerability-exceptions.json);
they are bounded review decisions, not claims that an advisory is fixed or
permanent guarantees. Electron Cash Docker requires the verified BCH-specific
`libsecp256k1` backend for private operations.

## Web Access and Recovery Controls

The web interface uses a password-only login form backed by
`auth-session`/`forward_auth` and session cookies. The form has no username
field, and no username is required.
Browser-native challenge authentication and a password-derived browser verifier
are not used as the access mechanism. WebSocket and noVNC traffic is protected
by the same authentication check as the browser assets.

Opaque random bearer tokens are verified against SHA-256 digests in
`/auth-data/sessions.sqlite`, never stored raw. This owner-only project volume
(directory 0700, database/sidecars 0600) is mounted only into non-root UID/GID 10001
auth-session; rootfs remains read-only and capability-free. Short SQLite
transactions, bounded lock waits and FULL synchronization commit creation/
revocation before success. A persisted salted PBKDF2 password verifier and
credential generation atomically revoke all sessions on actual password change;
same-password recreation preserves the generation and stale authorities cannot
issue tokens. Absolute expiry is 30 minutes temporary or 30 days remembered;
passive probes do not renew it. Logout and auth-volume-only reset invalidate
durably. Corrupt/unavailable/unsupported persistence fails closed and unhealthy,
with non-secret diagnostics, no RAM fallback and no self-deletion.

GUI end/deletion is not web logout. The terminal page inhibits RFB retries but
keeps one timeout/backoff-bounded same-origin HTTP observer. New ready generations
permit one direct protected-page navigation; explicit 401 permits login navigation.
Network/5xx/origin-policy 403 failures do not prove invalid authentication. Status
is no-store and reveals only GUI generation/state/readiness, never session lists,
token/password metadata or wallets. Existing HttpOnly/SameSite/appropriate Secure
cookies and CSRF rules remain. Token hashes prevent direct bearer reuse after
read-only disclosure, not writable-database or full application compromise.
Auth storage is excluded from wallet backups/restores, source/release bundles
and sanitized evidence. The operating guide provides a narrow auth-only reset.

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

Read-only `/auth/gui-session` 401 responses (including query variants) are
excluded from guess counting; expired/missing cookies are not failed passwords.
Failed login and unauthorized protected-resource enforcement remains. If expiry/
revocation races a valid probe and protected HTML navigation, the auth check
retains HTTP 401 and serves only a CSP-hashed, fixed same-origin login navigation;
it grants no access and reflects no credentials or navigation target.

The POSIX backup launcher has been exercised on Linux. When an existing
host-side restore-state directory is present, its permission check uses
GNU-style `stat -c`; macOS/BSD `stat` is not a demonstrated host. Archive
processing remains inside the image. Backup/restore automatically quiesces only
the Electron Cash writer, uses an interactive passphrase with AES-256 GPG
encryption, validates the existing
manifest and hashes, snapshots the current named volume to a temporary Docker
volume, and restores that snapshot automatically if replacement or health
verification fails.

## Runtime Security Boundary

Long-running services have read-only roots, no-new-privileges, bounded PID/CPU/
memory and rotating Docker logs. Wallet GUI/daemon processes run as 10001:10001
with zero effective capabilities. First-use volume ownership requires a brief
root bootstrap with CHOWN, DAC_OVERRIDE, FOWNER, SETUID and SETGID only.
The cookie-copy helper needs root with CHOWN/DAC_READ_SEARCH, no network, and
read-only host mounts. Caddy runs as root without Linux capabilities to preserve
shared admin/ban-state ownership; fail2ban needs root/NET_ADMIN for namespace-local
packet enforcement. Auth-session and Tor remain non-root without capabilities.
No service is privileged; USB access is opt-in for the Ledger wallet only.

Wallet/configuration data stays under the named wallet volume. Browser
mode also writes a project-scoped generation/end-state volume containing no
wallet data or credentials. Siblings mount that channel read-only and supervise
only their own container processes; no Docker socket or host PID access is used.
Wallet confirmation, password, signing and file-deletion decisions remain under
Electron Cash's native controls; web authentication does not replace them.
Desktop cache, session bus, local runtime data and /tmp are bounded ephemeral
tmpfs. Caddy and fail2ban retain their necessary state/control/log volumes.
Raw RFB listens only on wallet loopback. Internal noVNC remains on the private
Compose bridge and is not host-published; host/public users enter through Caddy
and its session check. Docker-admin or arbitrary bridge-peer access is outside
the web-authentication isolation boundary. Tor is explicit SOCKS routing, not a
transparent egress firewall; plugins/host/browser are not automatically torified.

Tor uses `Sandbox=1`. Source verification and compatibility controls are
documented in the [Tor supply-chain notes](docs/tor-supply-chain.md).

See the [English guide](docs/USER-GUIDE.md) and
[Spanish guide](docs/USER-GUIDE-ES.md) for the public-exposure checklist, browser
keyboard limits, recovery and supported platform boundaries.
