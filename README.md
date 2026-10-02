<p align="center">
  <img src="docs/assets/electron-cash-docker-banner.png" alt="Electron Cash Docker — BCH Forge">
</p>

# Electron Cash Docker

[![Release checks | PASSED](docs/badges/release-checks.svg)](#validation)
[![Tests | ALL PASSED](docs/badges/tests.svg)](#validation)
[![Bandit | passing · 2026-10-02](docs/badges/bandit.svg)](SECURITY.md#automated-validation)
[![Trivy | passing · 2026-10-02](docs/badges/trivy.svg)](SECURITY.md#automated-validation)

Electron Cash Docker packages [Electron Cash](https://github.com/Electron-Cash/Electron-Cash),
the Bitcoin Cash SPV wallet, in a Docker deployment. Electron Cash can be used
through the default browser interface via noVNC, in a native desktop window on
Linux/X11 or macOS/XQuartz, or in headless mode with optional JSON-RPC. Wallet
data persists in Docker-managed volumes, wallet traffic uses Tor, and CashFusion
is available for manual use.

## Features

- Electron Cash 4.4.6 with persistent wallet and configuration data.
- Browser GUI through noVNC, plus Linux X11 and macOS XQuartz desktop modes.
- Mainnet, testnet, testnet4, scalenet, chipnet, and regtest support.
- Tor sidecar for Electron Cash and CashFusion traffic explicitly configured
  to use it.
- CashFusion enabled by default; automatic fusion is disabled by default.
- Supported headless mode and optional password-protected JSON-RPC.
- Encrypted, managed wallet backup and restore.
- Non-root wallet container and verified bundled Flipstarter Helper plugin.

## Demo

![Electron Cash Docker testnet4 demo](docs/assets/electron-cash-docker-demo.gif)

This demonstration uses testnet4, whose coins have no monetary value. It shows
the real Electron Cash Docker browser interface with isolated disposable test
data, the testnet4 network view, Tor and CashFusion configuration, and the
verified Flipstarter external plugin. Automatic fusion remains opt-in; no real
BCH or live CashFusion round is involved.

## Quick Start

Requirements:

- Docker Engine 20.10 or newer.
- Docker Compose v2.24 or newer.
- At least 2 GB of available memory and approximately 2 GB of disk space.

```bash
git clone https://gitlab.com/bchforge/electron-cash-docker
cd electron-cash-docker
cp .env.example .env
```

Edit `.env` and set `BASIC_AUTH_PASSWORD` to a real password. Compose requires
the value before it creates containers; write `$$` for each literal `$` in the
password. Then build and start the default browser deployment:

```bash
docker compose build
docker compose up -d
```

Open <http://127.0.0.1/> and enter the password. The first start opens Electron
Cash's wallet setup wizard. Docker Compose creates the
`bchforge-electron-cash-data` volume, mounted at
`/home/electroncash/.electron-cash`. It persists across restarts and normal
`docker compose down` operations. The wallet container runs as UID/GID
`10001:10001`.

## Access Modes and Platforms

- **Browser:** Supported through noVNC and the normal/default GUI path. This is
  the supported Windows-friendly option when Docker itself is available.
- **Native desktop window:** Linux is supported through X11; macOS is supported
  through XQuartz. Both open Electron Cash directly in a desktop window without
  using noVNC. Windows has no native desktop-window mode that is currently
  supported, documented, or validated.
- **Headless:** Supported. Start the daemon without a GUI:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.headless.yml up -d
  docker compose exec --user 10001:10001 electron-cash \
    /opt/electroncash-venv/bin/electron-cash daemon status
  ```

- **JSON-RPC:** Optional, disabled by default, and password-protected when
  enabled. Use the headless and RPC overlays with non-empty JSON-RPC credentials
  in `.env`; the host port is bound to `127.0.0.1`:

  ```bash
  docker compose -f docker-compose.yml -f docker-compose.headless.yml \
    -f docker-compose.rpc.yml up -d
  ```

  The base Compose configuration still requires `BASIC_AUTH_PASSWORD` during
  interpolation in headless mode. JSON-RPC has separate credentials.

- **Ledger:** Supported only through the documented native Linux Docker Engine
  hardware path, with X11 and a supported Ledger device. It is not supported on
  macOS or Windows Docker Desktop, or for other hardware wallets. See
  [platform validation](docs/platform-validation.md) for the normal Compose
  command, USB group setup, and maintainer-only test boundaries.

### Linux X11 Desktop

Run from a local Linux graphical session with an authenticated X11/XWayland
display. Keep the host Xauthority file at its normal location; Compose validates
the active cookie and copies it into a private, read-only runtime volume for the
wallet container. No manual cookie conversion, ownership change, or `xhost`
command is needed.

```bash
test -n "$DISPLAY"
docker compose -f docker-compose.yml -f docker-compose.gui.yml up -d
```

The host cookie and X11 socket are mounted read-only; the host cookie is never
rewritten or re-owned. Stop the GUI deployment before switching back to browser
mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml down
docker compose up -d
```

For an SSH-forwarded display, use the maintainer platform runner documented in
[`docs/platform-validation.md`](docs/platform-validation.md); a forwarded
`localhost` display is not mounted directly into the container.

### macOS XQuartz Desktop

Install and start XQuartz, then run the desktop launcher. It manages the
temporary XQuartz access needed by Docker Desktop and restores its prior
settings when it exits:

```bash
bash scripts/mac-gui.sh
```

## Networks

Supported networks are `mainnet`, `testnet`, `testnet4`, `scalenet`, `chipnet`,
and `regtest`. `mainnet` is the default. Set `NETWORK` to select the chain, for
example:

```bash
NETWORK=chipnet docker compose up -d
```

Wallet and configuration state is isolated per network within the persistent
volume. Keep backups for each network separately and select the same network
when restoring. Compose overlays select execution mode, not network; there are
no network-specific Compose overlays.

Test-network servers and CashFusion rounds are not guaranteed to be available.
Regtest requires a reachable compatible server.

## Wallet Backup and Restore

Persistence is not a backup. Keep the recovery seed independently and create
encrypted backups with the managed scripts:

```bash
./scripts/backup.sh backup <name>
./scripts/backup.sh restore <name>
```

On Windows, use PowerShell:

```powershell
.\scripts\backup.ps1 backup <name>
.\scripts\backup.ps1 restore <name>
```

Backup prompts for an encryption passphrase. Restore validates the archive and
network, warns before replacing the active wallet, and keeps a temporary Docker
volume for rollback if restoration fails. The backup must be restored with the
same `NETWORK` selected; other network data in the volume is preserved. The
POSIX launcher is documented for Linux; on Windows use the PowerShell launcher.

## Tor and CashFusion

Electron Cash and CashFusion use the internal `tor-proxy:9050` SOCKS endpoint by
default. This is not a transparent gateway: it does not route the browser, host,
or other applications through Tor.

CashFusion is enabled by default for manual use, with automatic fusion disabled
by default (`CASHFUSION_AUTO_FUSE=false`). To disable the plugin entirely, set
`CASHFUSION_ENABLED=false` in `.env`. Initial settings only fill missing wallet
preferences; changes made in Electron Cash are preserved. Encrypted wallets
still require their normal wallet password before CashFusion can start.

The bundled Flipstarter Helper is a Qt plugin. Plugins are verified during the
image build and are not downloaded at runtime.

## Configuration and Upgrades

The default gateway listens on localhost. For a public deployment, set
`CADDY_SITE_ADDRESS` to your domain and `CADDY_EDGE_BIND=0.0.0.0`, configure DNS,
and allow inbound TCP ports 80 and 443. Caddy obtains a public TLS certificate
through ACME. For local use, the default `localhost` configuration is available
over HTTP; local HTTPS uses Caddy's internal certificate authority.

Compare your `.env` with the new `.env.example` when upgrading. Git does not
update `.env`, so preserve your settings while updating version and integrity
pins. Check the resolved images before starting:

```bash
docker compose --env-file .env config --images
docker compose build
docker compose up -d
```

## Security Notes

- Set a wallet password in Electron Cash before using meaningful funds. Keep
  the recovery seed offline and never put it in `.env`.
- A compromised Docker host can read the Docker-managed wallet volume.
- The gateway requires `BASIC_AUTH_PASSWORD`; noVNC is not published directly
  on the host. Keep the default host binding on localhost unless intentionally
  configuring a public deployment.
- Tor applies only to Electron Cash and CashFusion traffic configured for the
  internal SOCKS endpoint; it does not protect the browser, host, or wallet
  volume.
- Persistence is not a backup. Keep independent recovery and encrypted backup
  copies.
- JSON-RPC is disabled by default. When enabled, use non-empty credentials and
  retain the localhost-only host binding.

## Validation

The badges at the top of this README link here. Maintainer validation has a
static/Compose fast path and a full provider-independent release gate:

```bash
./scripts/ci.sh fast
./scripts/ci.sh gate
```

The gate includes a cold Compose first run, multi-network lifecycle and
backup/restore validation, authenticated Linux GUI/Xauthority under Xvfb, macOS
launcher contracts, and the synthetic Ledger backend. These are automated
checks, not physical-host certification. See
[`docs/platform-validation.md`](docs/platform-validation.md)
for user-run Compose paths and opt-in physical checks. The release gate runs
locally through the repository scripts and does not require a hosted CI runner.

## Release Roadmap

- [x] `v0.1`: browser access, persistent wallet data, Tor, the CashFusion plugin
  with opt-in auto-fusion, and its historical Testnet4 override.
- [x] `v0.2`: secure plugin distribution, Flipstarter Helper, headless mode, and
  optional password-authenticated JSON-RPC disabled by default.
- [x] `v0.3`: HTTPS, form/session authentication, fail2ban, a fixed
  persistence-preserving CashFusion first-use profile, plus encrypted backup
  and tested restoration.
- [x] `v0.4`: native Linux X11 and macOS XQuartz desktop access, isolated state
  for every network supported by the pinned Electron Cash version, and opt-in
  Ledger support on native Linux Docker Engine.
  See [Access modes and platforms](#access-modes-and-platforms) for operating
  details.
- [ ] `v1.0`: further runtime hardening, interface-language selection,
  maintainer-run security validation, documentation of the built-in noVNC
  virtual keyboard, English and Spanish setup and security documentation,
  expanded browser, arm64, and integration tests, and a release demo.

## Project Links

- [Project repository](https://gitlab.com/bchforge/electron-cash-docker)
- [CHANGELOG.md](CHANGELOG.md)
- [Platform validation](docs/platform-validation.md)
- [Security policy](SECURITY.md)
- [Tor supply-chain notes](docs/tor-supply-chain.md)

## License

MIT. See [LICENSE](LICENSE). Tor is distributed under the Tor Project's 3-clause
BSD license with its bundled notices.
