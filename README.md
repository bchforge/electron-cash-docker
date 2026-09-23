<p align="center">
  <img src="docs/assets/electron-cash-docker-banner.png" alt="Electron Cash Docker — BCH Forge">
</p>

# Electron Cash Docker

[![Release checks | PASSED](docs/badges/release-checks.svg)](#validation)
[![Tests | ALL PASSED](docs/badges/tests.svg)](#validation)
[![Bandit 1.9.4 | 0 findings - 2026-09-22](docs/badges/bandit.svg)](SECURITY.md#automated-validation)
[![Trivy 0.74.0 | 0 fixable HIGH / CRITICAL - 2026-09-22](docs/badges/trivy.svg)](SECURITY.md#automated-validation)

Electron Cash Docker packages [Electron Cash](https://github.com/Electron-Cash/Electron-Cash),
the Bitcoin Cash SPV wallet, for a local browser through noVNC. It includes
persistent wallet data, Tor networking, and a CashFusion plugin controlled by a
single enable toggle.

## Features

Electron Cash Docker currently provides:

- A self-hosted Electron Cash wallet with browser access through noVNC and
  persistent wallet/configuration data.
- A separate, hardened Tor sidecar for Electron Cash SPV and CashFusion traffic
  explicitly configured for the Docker-internal `tor-proxy:9050` endpoint.
- CashFusion is enabled by default (`CASHFUSION_ENABLED=true`) with automatic
  fusion disabled by default (`CASHFUSION_AUTO_FUSE=false`); its documented
  `.env` profile supplies initial values only for missing native wallet keys.
- Verified external plugin distribution with pinned source, versions, archive
  hashes, deterministic package hashes, and the bundled Flipstarter Helper.
- Both the default GUI/noVNC deployment and an explicit headless daemon mode.
- Optional password-protected JSON-RPC, disabled by default and exposed only
  through the localhost-only Compose override.
- An isolated testnet4 override for disposable, no-funds testing.

Electron Cash Docker is developed as an independent open-source project. See
the [GitLab repository](https://gitlab.com/bchforge/electron-cash-docker) and
the project documents below for release history, funded future scope, and
validation/security details.

The badges above summarize project validation. See [SECURITY.md](SECURITY.md)
for stable security information and reporting guidance.

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
- Docker Compose v2. The headless override uses the Compose `!reset` merge tag;
  use a plugin that can parse that syntax.
- At least 2 GB of available memory.
- Approximately 2 GB of disk space for the image.

```bash
git clone https://gitlab.com/bchforge/electron-cash-docker
cd electron-cash-docker
cp .env.example .env
# Before starting, edit .env and set BASIC_AUTH_PASSWORD to a real password
# in cleartext. Write $$ for each literal $ in that password.
# Compose rejects the intentionally empty value before creating containers.
docker compose build
docker compose up -d
```

Open <http://127.0.0.1/> and sign in on the password-only form using the
password configured in `.env`. The private `auth-session` service validates the
password, and Caddy uses `forward_auth` to gate the protected noVNC assets and
WebSocket. It issues a browser-session-only HttpOnly cookie unless `Remember
this session` is checked; returning to the root then asks for the password
again. A checked remember option re-enters directly while its long-lived
session remains available. There is no username field, host verifier file, intermediate wallet screen,
or native browser Basic Auth challenge. The first
start opens Electron Cash's wallet setup wizard. Docker Compose creates the named volume
`bchforge-electron-cash-data` automatically. It is mounted at
`/home/electroncash/.electron-cash` and survives container restarts and normal
`docker compose down` operations. On first use the container adds a
`.electron-cash-docker` marker after checking the empty volume. Later starts
reject invalid markers, symbolic links, incompatible ownership, and ineffective
access instead of changing existing data recursively.
The Tor image is built locally during `docker compose build` from the pinned
Tor Project source release; no third-party Tor container image is pulled. Tor
client state is stored separately in `bchforge-electron-cash-tor-data`.

### If the Page Does Not Load

If the page does not load, check the service status and auth-session log:

```bash
docker compose ps
docker compose logs auth-session
```

If `BASIC_AUTH_PASSWORD` is unset or empty, Compose stops before creating
containers with this message:

```text
BASIC_AUTH_PASSWORD must be set to a real password before starting Electron Cash Docker
```

Older `.env` files may still contain `CHANGE_ME...`; auth-session rejects that
legacy placeholder as a second safeguard. Edit `.env` and set a real
`BASIC_AUTH_PASSWORD`, then start the stack again:

```bash
docker compose up -d
```

Then retry the page.

### Verified Plugins

The root [`plugins.json`](plugins.json) is the trusted plugin manifest. Each
entry records the upstream source, release version, source archive SHA-256,
deterministic plugin ZIP SHA-256, and activation state.
The Docker build fetches the exact archive, verifies it before extraction,
validates the plugin metadata, creates a deterministic ZIP, and fails closed on
either digest mismatch. The runtime verifies the image artifact again before
copying it to Electron Cash's network-specific `external_plugins` directory.

The bundled external plugin is Flipstarter Helper v1.5.0 from
[`flipstarter/flipstarter-electron-cash`](https://gitlab.com/flipstarter/flipstarter-electron-cash).
It is a Qt plugin and is not represented as a headless CLI feature. The image
does not download plugins at runtime and does not implement a plugin registry or
marketplace.

The build path can be checked without starting a container:

```bash
bash docker/plugins/build_plugins.sh
bash docker/plugins/build_plugins.sh --verify-only
```

`--verify-only` requires an existing ZIP and never falls back to a remote
artifact or a latest version.

### Headless Mode

Headless mode is an explicit alternative to the default GUI/noVNC mode. It uses
the same Electron Cash image, named wallet volume, network-specific data path,
CashFusion configuration, UID/GID, and Tor sidecar. It starts Electron Cash's
upstream daemon through a Qt-free wrapper and does not start Xvfb, Openbox,
x11vnc, or websockify.

```bash
docker compose -f docker-compose.yml -f docker-compose.headless.yml up -d
docker compose exec --user 10001:10001 electron-cash \
  /opt/electroncash-venv/bin/electron-cash daemon status
```

The base Compose file still requires a non-empty `BASIC_AUTH_PASSWORD` in
`.env` during interpolation, even though headless mode does not start the
`auth-session`, Caddy, or fail2ban services. This is a Compose prerequisite,
not active headless web authentication; JSON-RPC credentials are separate and
remain disabled unless its explicit override is selected.

An encrypted production wallet is not automatically unlocked. The supported
security boundary is operator loading/unlocking through Electron Cash. The
testnet4-only `WALLET_AUTO_CREATE` and `TEST_WALLET_PASSWORD` path remains
available for disposable test runs only.

### Optional JSON-RPC

JSON-RPC is disabled in the default GUI deployment and in the plain headless
override. Do not publish the RPC port by editing the normal Compose file. For a
explicit RPC override and non-empty credentials in the ignored `.env` file:

```bash
docker compose -f docker-compose.yml \
  -f docker-compose.headless.yml -f docker-compose.rpc.yml up -d
```

The daemon listens on its container interface, while Docker publishes the host
socket only as `127.0.0.1:${JSONRPC_HOST_PORT:-50001}`. Missing, empty, malformed,
or unsupported credentials fail before daemon startup. The password is not
logged, put in command arguments, or included in generated URLs. Docker
administrators may inspect the configured environment, including credentials,
as part of the deployment's host-level trust boundary. Remove the RPC override
and recreate the service to return to the default disabled state.

### Wallet Persistence

Wallet data is managed by Docker and persists across normal restarts. Do not
edit live Electron Cash files or use Docker's internal storage paths as a normal
management method. Volume deletion is permanent, so keep the recovery seed
independently; persistence is not a backup. v0.3 provides a managed encrypted
backup and restore workflow:

```bash
./scripts/backup.sh backup <name>
./scripts/backup.sh restore <name>
```

On Windows PowerShell, use the native launcher instead:

```powershell
.\scripts\backup.ps1 backup <name>
.\scripts\backup.ps1 restore <name>
```

The POSIX wrapper has been exercised on Linux with Docker and the Compose v2
plugin. When an existing host-side restore-state directory is present, its
permission check uses GNU-style `stat -c`; macOS/BSD `stat` is not a
demonstrated host. On Windows use the PowerShell launcher; archive processing
still runs inside the Electron Cash image, so host Python, GPG, and archive
tools are not required. The wrapper refuses to overwrite an existing named
archive, and restore mounts the source archive read-only. This is no-overwrite
behavior, not filesystem immutability; the archive is stored as
`backups/<name>.ecd.gpg` and restore does not change it.
This validation was Linux-only and does not certify native macOS or Windows
runtime execution.

The encrypted archive contains a manifest and a gzip-compressed tar payload.
For mainnet it includes `.electron-cash-docker`, `config`, `wallets`, and
`mainnet`; for testnet4 it includes `.electron-cash-docker` and `testnet4`.
Paths containing `.env`, `logs`, `log`, `cache`, `caches`, `tmp`, or `run` are
excluded. Electron Cash `config` files are copied after removing recognized
password and RPC credential keys. The image helper encrypts the archive with
AES-256 GPG; backup prompts for and confirms a passphrase, while restore asks
for it once and validates the encrypted manifest, network, Electron Cash
version, paths, sizes, and SHA-256 hashes before changing the live volume.

If Electron Cash is running, it is stopped briefly to create a consistent backup
and restarted automatically with a health check. If it is stopped, the backup
does not start it. Before restoring, Electron Cash Docker validates the named
backup, warns that the active wallet will be replaced, and asks for
confirmation. It snapshots the current live state to a temporary, task-owned
Docker volume, replaces the live volume, and preserves whether Electron Cash
was running or stopped. A replacement, start, or health-check failure during
restore triggers rollback to that snapshot and an attempt to return Electron
Cash to its prior state. If rollback or cleanup also fails, the launcher keeps
the interruption marker and snapshot for its existing recovery path and
reports the failure; host or Docker loss can still prevent recovery, and no
filesystem-level safety guarantee is implied.

## Tor And CashFusion

Electron Cash routes SPV traffic through the internal `tor-proxy` service by
default.

Electron Cash Docker deliberately uses this standalone `tor-proxy` service
instead of relying on a Tor daemon owned by the Electron Cash application. Tor
is independently versioned, health-checked, restarted, and hardened in its own
container boundary, without access to the wallet volume. Electron Cash and
CashFusion explicitly consume its stable Docker-internal SOCKS endpoint at
`tor-proxy:9050`; future components may reuse it only when explicitly
configured. Electron Cash 4.4.6's upstream packaged Tor does not replace this
service. This is not a transparent gateway: only traffic explicitly configured
for `tor-proxy:9050` uses it.

The `tor-proxy` image is a BCH Forge multi-stage build in
[`docker/tor/`](docker/tor/). It downloads Tor `0.4.9.11` from the official Tor
Project source distribution, verifies the Tor Project release signature and
the pinned SHA-256 before compilation, and runs the resulting client as UID/GID
`10001:10001`. The signed release process, key fingerprints, Docker stages,
license handling, and update procedure are documented in
[`docs/tor-supply-chain.md`](docs/tor-supply-chain.md).

Only SOCKS5 is enabled at `tor-proxy:9050`. The endpoint is Docker-internal:
Compose uses `expose`, not a host `ports` mapping. The Tor container has no
ControlPort, HTTP proxy, DNS proxy, relay, bridge, onion-service, Nyx, or
Lyrebird capability. Tor's local healthcheck tests the SOCKS handshake without
contacting an external website; acceptance tests separately verify bootstrap
and a Tor-routed connection.

CashFusion is enabled by default (`CASHFUSION_ENABLED=true`) and automatic
fusion is disabled by default (`CASHFUSION_AUTO_FUSE=false`). The other
CashFusion variables are initial wallet defaults, not a policy that is re-applied
at every start. Older `.env` files that omit the CashFusion variables use the
same defaults:

```bash
# Default: CashFusion available for manual use, automatic fusion disabled.
docker compose up -d

# Optional: disable the CashFusion plugin entirely.
CASHFUSION_ENABLED=false docker compose up -d
```

`CASHFUSION_ENABLED=false` disables the plugin and prevents fusion activity.
With the plugin enabled, the first eligible wallet open applies the
missing-only profile from `.env`: auto-fusion `false`, selector `mode=count`,
selector count/target `10`, `queued_autofuse=4`, fuse depth `3`, one
self-fusion player, and confirmed-only operation. This keeps manual CashFusion
available without starting automatic fusion. The environment initializes only
missing native wallet keys; after that, GUI values are authoritative. Existing
wallet values, including GUI changes such as enabling auto-fusion or changing
depth `3` to `7`, are preserved on later starts. A missing wallet is a safe
no-op. For an encrypted wallet, Electron Cash still requests its normal
password before fusion can start; the environment-password exception is limited
to the automated testnet4 path described above.

The selector interface supports all three native modes: `count` uses
`CASHFUSION_SELECTOR_COUNT`, `size` uses `CASHFUSION_SELECTOR_SIZE_BCH` and
converts BCH exactly to satoshis, and `fraction` uses
`CASHFUSION_SELECTOR_FRACTION` as a probability from `0.0` to `1.0`. The
recommended default remains `count` with `10`. Inactive selector variables do
not affect the selected mode. There are no environment controls for target
amount, fee budget, minimum UTXO, or CashFusion-specific Tor host/port.
CashFusion uses the pinned Electron Cash behavior and its own safety limits;
enabling the plugin does not guarantee completed rounds, privacy against every
threat, or compatible servers.

## Operation And Development

### Validation

Run the project checks locally:

```bash
./scripts/ci.sh fast
./scripts/ci.sh sast
./scripts/ci.sh acceptance
./scripts/ci.sh gate
```

- `fast`: source, pin, static regression, and Compose-resolution checks.
- `sast`: Bandit static analysis.
- `acceptance`: builds images and runs runtime checks.
- `gate`: runs the complete release validation.

The default Compose stack publishes only Caddy, protects the noVNC assets and
WebSocket with a password-only form/session gate through `auth-session` and
`forward_auth`, and runs fail2ban in Caddy's task-owned network namespace.
Local configuration serves HTTP directly on `:80` and HTTPS directly on `:443`
as independent listeners; HTTP does not redirect to HTTPS. Local HTTPS uses
Caddy's internal certificate authority, so a browser or operating system may
need that CA trusted before it reports a trusted certificate. Use
`http://localhost/` or `http://127.0.0.1/` for local access. VS Code Remote Port
Forwarding can forward the loopback `:80` listener, but an arbitrary `Host`
header is not an authentication authority: `auth-session` accepts the
configured site host and the local `localhost`/`127.0.0.1`/`::1` aliases only.
For an external domain, use the configured domain as the host; HTTP `:80`
redirects to HTTPS `:443`, and Caddy obtains a publicly trusted TLS certificate
automatically through ACME.

Local configuration:

```dotenv
CADDY_SITE_ADDRESS=localhost
CADDY_EDGE_BIND=127.0.0.1
CADDY_HTTP_HOST_PORT=80
CADDY_HTTPS_HOST_PORT=443
```

Public deployment example:

```dotenv
CADDY_SITE_ADDRESS=ecd.example.org
CADDY_EDGE_BIND=0.0.0.0
CADDY_HTTP_HOST_PORT=80
CADDY_HTTPS_HOST_PORT=443
```

Create DNS A/AAAA records pointing to the server's public IP and allow inbound
TCP 80/443.

The Quick Start commands above are the complete normal first-run contract.
Validation and maintenance scripts are optional and are not required to build
or start the stack.

Use raw Docker Compose from the repository root. The private auth-session
service validates the required password for password-only session auth. Missing,
empty, placeholder, or malformed auth input fails closed. Legacy username
variables are ignored. The password and session cookie are not written to the
generated Caddyfile, Electron Cash upstream, or access logs.

```bash
docker compose build
docker compose up -d
docker compose ps
docker compose logs -f electron-cash
docker compose down
```

When upgrading, compare your existing `.env` with the new `.env.example`
before rebuilding. `.env` is a local file and is not updated by Git, so it may
continue to select an older Electron Cash image after the repository has been
updated. Preserve intentional local settings while updating the version and
integrity pins rather than overwriting the whole file. Before starting the
stack, confirm the resolved images:

```bash
docker compose --env-file .env config --images
```

For the supplied configuration, this should include `electron-cash:4.4.6`,
`bchforge/electron-cash-docker-tor:0.4.9.11`,
`electron-cash-docker-auth-session:0.3`, `electron-cash-docker-caddy:0.3`,
and `electron-cash-docker-fail2ban:0.3`.

The Electron Cash and noVNC versions in `.env` have matching commit and archive
integrity pins. Update each version and all of its pins together. The Ubuntu
base image is pinned by digest, and the Tor source version and SHA-256 are
required build pins in `.env.example`; builds do not silently consume a
different source artifact under the same version.

The login and noVNC pages are titled `Electron Cash Docker` and use the bundled
SVG favicon; the supplied `.env.example` pins noVNC `1.6.0`.

To inspect or rebuild only the Tor component:

```bash
docker compose --env-file .env.example build tor-proxy
docker run --rm --entrypoint /usr/local/bin/tor \
  bchforge/electron-cash-docker-tor:0.4.9.11 --version
python3 tests/test_tor_proxy.py
```

After building the image, run the CashFusion state matrix with:

```bash
python3 tests/test_cashfusion_states.py
```

Run the capability-focused plugin, Flipstarter, headless, and JSON-RPC checks with:

```bash
python3 tests/test_plugin_distribution.py
python3 tests/test_flipstarter_plugin.py
python3 tests/test_headless.py
python3 tests/test_rpc.py
```

These commands cover persistence, Tor, CashFusion, noVNC, testnet4, plugin,
headless, and JSON-RPC behavior.

Source code and current project documentation are maintained in English.

## Security Warnings

- The noVNC port is internal to the Compose network and is not published on the
  host. Caddy is the only user-facing web service.
- The gateway always requires `BASIC_AUTH_PASSWORD`; any legacy username
  variable is ignored. The private auth-session service provides password-only
  form/session login with browser-session-only or long-lived remembered HttpOnly
  cookies; Caddy protects noVNC assets and `/websockify`, while fail2ban uses
  the real client address path.
- Fail2ban defaults to 5 failures in 600 seconds, a 3600-second ban, and
  loopback addresses in `FAIL2BAN_IGNOREIP`. Enforcement runs in the shared
  Caddy network namespace. Direct clients are identified from the connection
  peer and can receive the namespace-local packet DROP; Cloudflare forwarded
  identity is trusted only at Caddy's layer from the pinned Cloudflare CIDR
  set, so arbitrary forwarded headers and packet-level drops through every
  proxy are not supported.
- Set a wallet password inside Electron Cash before using meaningful funds.
- Keep the recovery seed offline and never put a real seed in `.env`.
- A compromised Docker host can read the Docker-managed wallet volume.
- Persistence is not a backup. Maintain independent recovery and backup plans.
- Tor protects only the configured Electron Cash and CashFusion traffic through
  `tor-proxy:9050`, not the browser, host, wallet volume, or every application
  on the machine.
- The internal passwordless VNC endpoint shares a Docker network with the
  bundled Tor proxy. Attach no additional containers to that network.
- Headless mode and optional JSON-RPC are supported features. RPC remains
  disabled by default and the password-protected host mapping is localhost-only.

## Testnet4 Testing

The normal setup uses mainnet. For no-funds testing, stop the current stack and
start the testnet4 override:

```bash
docker compose down
docker compose -f docker-compose.yml \
  -f docker-compose.testnet4.yml up -d
```

The override starts Electron Cash with the `--testnet4` flag. With the default
Docker-managed volume, testnet4 data is kept under the internal
`/home/electroncash/.electron-cash/testnet4` directory. Mainnet data remains at
the volume root. Stop the current stack before switching between mainnet and
testnet4 because both paths use the same data volume. Do not use this
environment for real funds.

For an automated encrypted test wallet, use the testnet4-only variables:

```bash
WALLET_AUTO_CREATE=true \
TEST_WALLET_PASSWORD=cashfusion-test-password \
CASHFUSION_ENABLED=true \
docker compose -f docker-compose.yml \
  -f docker-compose.testnet4.yml up -d
```

The generated seed is suppressed from container logs. Mainnet rejects
`WALLET_AUTO_CREATE=true` and any non-empty `TEST_WALLET_PASSWORD`.
`TEST_WALLET_PASSWORD` is intentionally read from the environment only for this
automated testnet4 path and must never contain a production wallet password.

## Release Roadmap

- [x] `v0.1`: browser access, persistent wallet data, Tor, the CashFusion plugin
  with opt-in auto-fusion, and a test-only testnet4 override.
- [x] `v0.2`: secure plugin distribution, Flipstarter Helper, headless mode, and
  optional password-authenticated JSON-RPC disabled by default.
- [x] `v0.3`: HTTPS, form/session authentication, fail2ban, a fixed
  persistence-preserving CashFusion first-use profile, plus encrypted backup
  and tested restoration.
- [ ] `v0.4`: native X11 on the validated Linux path, XQuartz on the validated
  macOS path, every network supported by the pinned Electron Cash version with
  isolated data, and Ledger on native Linux Docker Engine.
- [ ] `v1.0`: hardening, including internal GUI service isolation,
  interface-language selection, maintainer-run security validation,
  documentation of the built-in noVNC virtual keyboard, English and Spanish
  setup and security documentation, expanded browser, arm64, and integration
  tests, demo, release evidence, and final accountability report.

## Project Documents

- [Project repository](https://gitlab.com/bchforge/electron-cash-docker).
- [CHANGELOG.md](CHANGELOG.md) for release history.
- [CAMPAIGN-PLAN.md](../../CAMPAIGN-PLAN.md) for the funded roadmap and future
  release scope.
- [SECURITY.md](SECURITY.md) for the security policy and reporting guidance.

## License

MIT. See [LICENSE](LICENSE).

Tor is separate upstream work and is distributed under the Tor Project's
3-clause BSD license with its bundled notices. The exact Tor license is copied
into the Tor runtime image at `/usr/share/doc/tor/LICENSE`; see
[`docs/tor-supply-chain.md`](docs/tor-supply-chain.md) for the supply-chain
record.
