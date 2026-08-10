# Changelog

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
