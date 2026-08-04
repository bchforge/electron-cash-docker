# Changelog

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
