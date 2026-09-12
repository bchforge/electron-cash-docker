# Changelog

## v0.2.1

- Added canonical fast and complete CI validation with isolated candidate-image
  builds, Compose resource guards, dependency checks, and bounded Trivy scans.
- Moved the directly pinned runtime Python dependencies into `requirements.txt`
  consumed by the real Docker build without changing their versions or package
  set.
- Added GitHub Actions CI, Dependency Review, first-party Python CodeQL
  analysis, Dependabot configuration, and the public vulnerability-reporting
  policy.
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
