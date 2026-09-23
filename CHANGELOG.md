# Changelog

## v0.3

- Added a unified Caddy gateway protecting the noVNC HTML/assets and
WebSocket/RFB endpoint with a password-only login form and session-based
authentication. Local deployments provide independent HTTP on port 80 and
HTTPS on port 443, while public-domain deployments redirect HTTP to automatic
 HTTPS. Caddy source and base-image identity are pinned and verified.
- Simplified first run to `.env` plus standard `docker compose build` and
`docker compose up -d`. Authentication credentials are handled internally at
runtime, so no host-side password hash file or startup wrapper is required.
- Added a task-owned fail2ban sidecar integrated with the Caddy edge, with
client-isolation and enforcement tests covering supported direct-client and
proxied access paths.
- Added a default-enabled, manual-first CashFusion initial wallet profile with
 environment-driven defaults, validation, missing-only persistence, and
 GUI-authoritative settings across restarts. Automatic fusion remains opt-in.
 The default selector is `count` with a target of `10`, queued autofuse is `4`,
  fuse depth is `3`, and Docker-internal Tor remains fixed at `tor-proxy:9050`.
- Added the two-command encrypted backup/restore workflow (`backup <name>` and
`restore <name>`) for Linux, macOS, and Windows hosts with Docker. It resolves
the active Compose wallet volume, quiesces only Electron Cash when required,
validates the GPG/manifest backup format, snapshots the current volume before
replacement, preserves the source backup, and automatically rolls back failed
restore, start, or health-check operations.
- Extended the release gate with remote-access, authentication,
CashFusion-policy, backup/restore, Compose-isolation, regression, and
image-security validation for the v0.3 release.

## v0.2.1

- Added canonical fast and complete CI validation with isolated candidate-image
  builds, Compose resource guards, dependency checks, and bounded Trivy scans.
- Moved the directly pinned runtime Python dependencies into `requirements.txt`
  consumed by the real Docker build without changing their versions or package
  set.
- Added provider-independent local Python SAST, base-vs-candidate dependency
  review, read-only dependency-update discovery, and local vulnerability
  reporting policy.
- Added repository-owned validation badges and an optional GitLab external
  commit-status adapter. GitLab merge enforcement displays the local result but
  does not define release correctness.
- Added a provider-independent local release gate with durable evidence,
  source vulnerability and secret scans, machine-enforced vulnerability
  dispositions, and fatal owned-resource cleanup checks. Hosted CI remains a
  supplemental wrapper rather than a release requirement.
- Pinned the Tor Dockerfile frontend by digest and retained the reviewed
  no-fix `ecdsa`/`CVE-2024-23342` finding as a narrow machine-checked
  exception.
- Added a bounded CVE-2024-23342 integration mitigation that requires the
  verified BCH-specific native ECC backend and fails closed instead of using
  the pure-Python private-operation fallbacks. The package advisory remains
  visible and is not represented as an upstream fix.
- Updated only the directly pinned protobuf package from `5.28.2` to `5.29.6`
  after the candidate scan identified fixable high-severity vulnerabilities;
  the remaining direct runtime pins are unchanged.
- Preserved the existing Electron Cash, noVNC, Tor, plugin, GUI, headless, RPC,
  persistence, CashFusion, and testnet4 contracts. This is a maintenance
  baseline, not a new funded product milestone, and it is not a deployment.

## v0.2

- Added the trusted external-plugin manifest and deterministic build-time source
  and ZIP SHA-256 verification.
- Added the official Flipstarter Helper v1.5.0 plugin from its pinned upstream
  release archive and byte-level hashes. Runtime plugin installation re-verifies
  the image artifact and never downloads plugins.
- Added explicit headless daemon mode without Xvfb, Openbox, x11vnc, or
  websockify, while retaining the named wallet volume, UID/GID, Tor sidecar,
  testnet4 path, and CashFusion configuration.
- Added optional upstream Electron Cash JSON-RPC. It is disabled by default,
  requires a non-empty password when enabled, and is published only through the
  explicit localhost-only RPC Compose override.

## v0.1.4

- Improved noVNC connection reliability with browser reconnect/keepalive support,
  generated HTML newline correctness, and the 30-second websockify heartbeat.
- Preserved shared, persistent x11vnc operation with `-forever -shared` and
  graceful GUI shutdown.
- Kept the accepted Electron Cash 4.4.6, BCH Forge Tor 0.4.9.11, named wallet
  volume, CashFusion defaults, and testnet4 behavior unchanged.

## v0.1.3

- Upgraded Electron Cash from 4.4.5 to 4.4.6 and updated its immutable commit
  and release-archive SHA-256 pins.
- Retained the standalone BCH Forge Tor 0.4.9.11 service as Electron Cash
  Docker's Tor runtime authority; the upstream packaged Tor update does not
  change this boundary.
- Documented the standalone Tor architecture and its explicit
  `tor-proxy:9050` consumers.
- Added regression validation that checks the resolved image tag and installed
  Electron Cash package version, alongside the existing Tor, CashFusion,
  persistence, noVNC, and testnet4 acceptance coverage.

## v0.1.2

- Replaced the third-party `dockurr/tor` runtime dependency with a repository-
  visible BCH Forge Tor Docker build.
- Tor 0.4.9.11 is compiled from the official Tor Project source release after
  signed-checksum and SHA-256 verification against pinned release authority.
- Added an auditable client-only `torrc`, non-root runtime identity, explicit Tor
  state volume, local SOCKS healthcheck, dropped capabilities, no-new-privileges,
  and read-only-root hardening.
- Added Tor-specific provenance, negative-integrity, runtime, bootstrap, SOCKS,
  isolation, and Electron Cash integration coverage while preserving v0.1.1
  wallet, mainnet, testnet4, and CashFusion behavior.

## v0.1.1

- Fixed cross-platform wallet persistence with the Compose-managed
  `bchforge-electron-cash-data` volume.
- Preserved non-root runtime execution and fail-closed startup behavior.
- Documented volume inspection, deletion, and the distinction between
  persistence and backup.

## v0.1

- Added browser access through noVNC.
- Added persistent wallet bind mounting.
- Added internal Tor proxy for Electron Cash SPV traffic.
- Added the default-enabled CashFusion plugin with separately configurable,
  opt-in auto-fusion; auto-fusion is ignored when the plugin is disabled.
- Added a test-only testnet4 Compose override with isolated wallet data.
- Added testnet4-only encrypted wallet auto-creation for CashFusion validation.
- Added localhost-only noVNC defaults and security warnings.
- Pinned base images and upstream source archives with immutable references and
  checksum verification.
- Added fail-closed configuration validation, atomic configuration writes, and
  safer wallet-directory ownership handling.
