# Electron Cash Docker v1.0 — User guide

[Español](USER-GUIDE-ES.md) · [README](../README.md) · [Security](../SECURITY.md)

## What is Electron Cash Docker?

Electron Cash Docker (ECD) lets you run the Electron Cash 4.4.6 Bitcoin Cash
(BCH) wallet on a computer you control. You can create or recover a wallet,
receive BCH, and review and send payments. Docker packages the application and
its dependencies; Docker Compose builds and starts the services together.

ECD is for people comfortable installing Docker, editing a settings file and
running terminal commands who want a reproducible wallet installation. The
usual route is **your browser on the same computer**. It displays the real
Electron Cash desktop through noVNC; your wallet runs in the container, not in
the browser. Native desktop windows and automation are optional routes.

Your wallet data persists in a Docker volume, but that volume is **not a backup**.
Keep your recovery seed offline and make separate encrypted backups. The web
login password, wallet encryption password and backup password protect different
things. Docker does not protect your wallet against a compromised host or a
Docker administrator. Tor and manual CashFusion are available, without an
anonymity guarantee.

This guide describes the **v1.0 release candidate**. Local preparation does not
mean it has been published: a public clone may not contain the candidate changes.
See the [release notes](../CHANGELOG.md#v10) and use the matching reviewed source
tree or bundle when working with the candidate.

### Find your task

- [Choose your setup](#choose-your-setup)
- [Install, log in and create your first wallet](#install-and-first-start)
- [Daily use and closing](#daily-use-and-closing)
- [Preferences, privacy and plugins](#preferences-privacy-and-plugins)
- [Backup, restore and recovery](#backup-restore-and-recovery)
- [Other access modes](#other-access-modes)
- [Upgrade and troubleshooting](#troubleshooting-and-upgrade)
- [Try it without funds](#try-it-without-funds)
- [Technical options and limits](#technical-options-and-limits)

## Choose your setup

For a personal wallet, start with **local browser access**. “Local” means
Docker and the browser run on the same computer: the default loopback address
does not accept connections from other computers. Choose another route only
when you need its capabilities. A remote browser needs explicitly configured HTTPS.

| Your environment or task | Route |
|---|---|
| Linux, macOS or Windows with Docker available | Local browser, the quick start below |
| Linux desktop with X11/XWayland | [Native window](#native-gui-and-ledger) with the GUI Compose file |
| macOS desktop | [Native window](#native-gui-and-ledger) with Docker Desktop and XQuartz |
| Windows desktop | Browser route; no supported native Windows window mode |
| Ledger hardware wallet | [Native Linux Docker Engine only](#native-gui-and-ledger), with GUI and hardware files |
| Automation without a window | [Headless daemon](#headless-and-rpc); JSON-RPC is a separate opt-in |
| Browser on another computer | [Protected remote access](#local-and-protected-remote-access) |

You need Docker Engine 20.10+ and Compose 2.24+ (additional Compose files use
`!reset`), at least 2 GiB of available memory and roughly 2 GiB for images.
Allow extra space and memory for fresh builds; download and build time varies.
Docker Desktop supplies the Docker environment for the documented macOS route
and the Windows browser route using Linux containers. XQuartz is only needed
for the macOS native window, not for the browser.

Run commands from the repository root. The quick start uses a POSIX terminal
on Linux/macOS; on Windows, use PowerShell and its copy command below, or a
WSL/Git Bash terminal with Docker accessible. Docker commands without shell
assignments work in either terminal. Linux scripts still need their documented
Linux environment; having Bash on Windows does not make every Linux mode supported.

Keep the same Compose project and additional files (also called overlays) for
start, stop, backup and upgrade. If you want to explore before creating a real
wallet, use the [separate Chipnet trial](#try-it-without-funds).

## Install and first start

This starts the local browser mode on **mainnet**, the network for real BCH.
For a trial, follow the isolated Chipnet instructions instead of changing this
installation into a demo.

1. Obtain the source for the version you intend to run. With Git installed,
   these commands download the public repository and enter its root directory:

   ```bash
   git clone https://gitlab.com/bchforge/electron-cash-docker
   cd electron-cash-docker
   ```

   For an unpublished candidate, open the supplied reviewed tree instead. The
   clone command alone does not install v1.0 candidate changes.

2. Create `.env`, your local settings file. **Skip this step if it already exists**
   so you do not overwrite your settings. In a Linux/macOS POSIX terminal:

   ```bash
   cp .env.example .env
   ```

   In Windows PowerShell, use this instead of `cp`:

   ```powershell
   Copy-Item .env.example .env
   ```

3. Open `.env` in a local text editor and set a strong, unique
   `BASIC_AUTH_PASSWORD`. This is the **web login password**, not wallet encryption.
   The template leaves it empty, so you must set it before starting. Write `$$`
   for a literal `$` in unquoted Compose dotenv values. Keep these settings for
   the normal local route:

   | Setting | Keep for local use |
   |---|---|
   | `NETWORK` | `mainnet` |
   | `CADDY_EDGE_BIND` | `127.0.0.1` |
   | `CADDY_SITE_ADDRESS` | `localhost` |
   | `WALLET_AUTO_CREATE` | `false` — create your wallet in Electron Cash |
   | `JSONRPC_ENABLED` | `false` |

   Never put a recovery seed or real wallet password in `.env`, commands or logs.
   Git ignores `.env`, but it is still a sensitive local file. Protect it;
   resolved Compose output can contain its secrets too.

4. Build and start (these Docker commands also work in PowerShell):

   ```bash
   docker compose build --pull
   docker compose up -d
   docker compose ps
   ```

   Wait for the services to become ready. The initial build downloads verified
   dependencies and can take longer than subsequent starts.

5. Open **`http://127.0.0.1/`** on that computer. Enter your web password and
   select **Connect**; there is no username. Leave **Remember this session**
   unchecked for a short session, or select it only on a trusted device.
   You should then see Electron Cash and, on a fresh volume, its wallet assistant.

   If port 80 is occupied, set `CADDY_HTTP_HOST_PORT=18080` (or another unused
   port), run `docker compose up -d` again and open `http://127.0.0.1:18080/`.
   Keep `CADDY_EDGE_BIND=127.0.0.1`. If the page is not ready, use the
   [symptom table](#diagnose-by-symptom).

### Create or restore your first wallet

Use the assistant inside **Electron Cash**, not the web login form. Give the
wallet a name you will recognise, then choose the appropriate route:

- **New wallet:** for an ordinary personal wallet, choose the standard wallet
  type and generate a new seed. Write the words, in order, on paper or another
  offline medium. Keep that copy somewhere
  private and protected from loss or damage, separate from this computer.
  Complete the assistant's seed check **before receiving funds**. Anyone who
  obtains the seed may control the wallet; a wallet password cannot revoke a
  disclosed seed.
- **Existing wallet:** choose the restore/import route and enter your seed or
  keys directly in the intended wallet field on a trusted computer. Follow the
  assistant for that wallet type. If you used a seed extension/derivation
  passphrase, preserve and enter it too; it is not the wallet encryption password.
  A `.ecd.gpg` archive is a different recovery route:
  follow [Restore an archive](#restore-an-archive).

Set a wallet encryption password before using meaningful funds and finish the
assistant. Check the network and connection status before using the wallet.
Keep seeds, private keys and wallet passwords out of support requests,
screenshots, browser clipboards and shared testing tools. The interface labels
can vary with the selected language and wallet type.

These secrets serve different purposes; do not treat them as interchangeable:

| Secret | What it protects or recovers |
|---|---|
| `BASIC_AUTH_PASSWORD` | Access to the browser desktop |
| Wallet password | The wallet's encrypted private data and wallet-authorized operations |
| Recovery seed | Recovery of the wallet's keys; anyone with it may control the funds |
| Backup archive password | Decryption of a `.ecd.gpg` backup |

A seed recovers keys for the corresponding wallet; it does not necessarily
recover labels, other metadata or plugin settings. Imported-key and watch-only
wallets may have no recovery seed: preserve the original recovery material for
your wallet type. Keep an encrypted archive as well as independent offline
recovery material.

## Daily use and closing

### Receive and send BCH

**To receive:** open the intended wallet in Electron Cash and use its Receive
view to obtain a receiving address. Check that you are on the intended network,
then share the address or its QR code with the sender. Watch the transaction
history for arrival and confirmations. A test-network address is not a mainnet
payment destination.

**To send:** use Electron Cash's Send view, enter the recipient's BCH address
and amount, and review the destination, network, amount and fee before approving.
Unlock the encrypted wallet when requested. For example, if paying an invoice
for `0.001 BCH`, check that the amount is in BCH, not another display unit.
After broadcasting, check the transaction history and confirmation status.
Closing a tab is not a way to cancel a payment already broadcast.
A watch-only wallet cannot sign payments: you need the corresponding private
keys or signing device, not just an address or public key.

### Where your data lives

The default Docker volume is `bchforge-electron-cash-data`: Docker-managed
storage mounted at `/home/electroncash/.electron-cash`. Wallet files and
configuration survive container restart, recreation and `docker compose down`.
**A persistent volume is not a backup. Never use `down --volumes` on real data.**
Use the same volume and project when returning to your wallet.

### End and restart a browser GUI session

Closing a browser tab disconnects that browser; it does not close the wallet.
In Electron Cash 4.4.6, **File > Quit / Ctrl+Q closes the current wallet window**.
Closing a window keeps its wallet file. **File > Delete** removes the selected
wallet file after Electron Cash's confirmation/password checks and completion
dialog; it is not a way to close a window. Cancellation or failed deletion
does not itself end the session.

Other open wallets, even minimized or hidden, and active open/create/restore
dialogs keep the application running. When you close the last wallet and finish
or cancel the last assistant, **the default browser project stops**: Electron
Cash, the web services (auth-session, Caddy and fail2ban) and Tor. The noVNC page
reports that the session ended and stops reconnecting. Independent headless/RPC
projects keep running; native modes have their own stop instructions.

To return, run:

```bash
docker compose up -d
```

Leave the same tab open: it can recover the desktop automatically while its
web cookie and server session remain valid, otherwise it returns to login.
Allow about 35 seconds after readiness, plus page loading, for recovery after
an outage. Ending the GUI is **not web logout**. Closed wallets retain their
data; deleted wallets are not recreated. If none remains, startup offers the
normal open/create assistant.

To stop the project from the terminal without removing containers:

```bash
docker compose stop
```

`docker compose start` starts existing containers. Prefer `up -d` after an
application-ended session or a settings change. To remove the project's
containers while keeping its persistent volumes:

```bash
docker compose down
```

Temporary connection failures reconnect. An unexpected wallet crash has
bounded `on-failure:5` retries; an unhealthy status alone does not trigger
automatic restart.

### Web login and session duration

The browser keeps an HTTP session cookie; the server keeps the session record
separately from your wallet. Without **Remember this session**, access expires
**30 minutes after login**. With it, access can last up to **30 days**. Using the
wallet does not extend either deadline. Closing the tab, closing Electron Cash
or stopping containers does not itself revoke the web session.

For a temporary session, returning to the site's root address `/` clears that
session and shows the login form. A valid remembered session instead returns to
the desktop. The logout endpoint and other expiry/revocation rules are in the
[session reference](#web-session-reference). Changing the web password and
recreating invalidates previous sessions. Wallet backups do not include web
sessions. Do not rely on closing a browser to remove a cookie: some browsers
restore session cookies when reopened.

### Typing in the wallet

Click the intended Electron Cash field before typing. Browser/system shortcuts
may intercept keys; noVNC's toolbar supplies extra keys and requests an on-screen
keyboard where supported. Check focus after switching windows. For layouts,
stuck modifiers and virtual input, see [browser keyboard](#browser-keyboard).
Never paste a seed into the browser clipboard; virtual input is not protection
against a compromised computer.

## Preferences, privacy and plugins

### Configure language and appearance

Electron Cash starts in English by default (`EC_LANGUAGE=en_US`). For a **new
configuration**, set `EC_LANGUAGE` in `.env` to any locale supported by the pinned
Electron Cash version. All 38 official EC 4.4.6 locale codes are supported;
an empty value (`EC_LANGUAGE=`) selects System.
Only invalid codes stop startup before wallet initialization. Existing configs
keep their saved Settings choice, including System or a historical unset key.
Select another language in Electron Cash Settings; changes survive restarts and
the ECD login reflects them on reload without restarting the container. Regional
variants and RTL are supported; documentation is provided only in EN/ES.
`DARK_MODE=true` selects the native dark theme; missing, empty or `false`
selects light, including clearing a saved dark preference. The parser ignores
surrounding whitespace and letter case; values other than true/false are rejected.

After editing `.env`, recreate with `docker compose up -d`, using the same
additional Compose files if applicable. A mere `restart` keeps the old
container environment. Language seeds only new configs, including native windows
and headless mode; theme applies at every launch and overrides the saved theme.
GUI theme changes can last for the current session. These options do not change
`LANG`, `LC_ALL`, `LANGUAGE` or noVNC's controls; headless has no GUI. The login
page follows the configured language; see [locale resolution and fallback](../README.md#configuration-and-upgrades).

### Tor and CashFusion

Tor can reduce disclosure of your connection's IP address to wallet servers.
It does not hide wallet files or protect a compromised computer.
`USE_TOR=true` sends configured Electron Cash SPV traffic (the wallet's server
connections) through `socks5:tor-proxy:9050`. CashFusion uses the internal Tor
endpoint. This does **not** route your browser, host or all plugins through Tor.
`USE_TOR=false` disables the SPV proxy. A healthy local SOCKS endpoint does not
guarantee that external servers are reachable.

CashFusion aims to make transaction links harder to analyse by combining
eligible coins with other participants. It is installed
and available with `CASHFUSION_ENABLED=true`, while
`CASHFUSION_AUTO_FUSE=false` keeps automatic participation off by default.
Begin with the GUI's manual controls; encrypted wallets still need their normal
unlocking. Set `CASHFUSION_ENABLED=false` to disable the plugin.
No server, eligible coin, completed round or anonymity is guaranteed. Test-network
fusion services may be absent; the Chipnet trial below must not start a round.

Initial wallet preferences fill only missing values: your GUI changes survive
restart, like language selections but unlike theme selections. The initial profile uses depth 3
and count selection targeting 10 coins; these do not promise a completed round
or a final coin count. Automatic participation remains off. Use the
[CashFusion reference](#cashfusion-controls) when changing selectors, queued
rounds or the separate fee/input limits. Invalid settings stop startup before
configuration changes.

### Choose the right network

Keep `NETWORK=mainnet` for real BCH. Other networks store separate wallet and
configuration data in the volume; switching networks can therefore show a
different or empty wallet. Set `NETWORK` in `.env`, then recreate with the same
mode files. Back up and restore with the matching network. The
[network reference](#networks-and-lifecycle) lists supported networks and
restrictions; the [isolated Chipnet trial](#try-it-without-funds) is the route
for practice without funds.

### Plugins

The bundled **Flipstarter Helper** is available as a Qt desktop plugin; it is
not a headless Flipstarter interface. Plugins are verified at build and startup,
not downloaded during use. Changing a bundled plugin requires source review
and a rebuild; see [plugin provenance](#plugin-provenance).

## Backup, restore and recovery

Use the seed or original keys to recover a wallet's keys; use an encrypted
archive to recover the selected network's saved wallet files and metadata.
Neither is a substitute for the other. Keep archives on separate secure storage,
away from the Docker host, with the archive password stored separately.
**Test recovery in an isolated deployment before relying on a backup.**

The archive covers selected-network wallet state, not the whole installation.
Keep your `.env` and deployment settings securely elsewhere; RPC credentials
are removed from archived configuration, and web authentication storage is not included.

The Linux wrapper is `scripts/backup.sh`; Windows has `scripts/backup.ps1`.
The POSIX wrapper has been validated on Linux. Its GNU `stat -c` permission
check means macOS host recovery is not a demonstrated wrapper path; macOS
desktop support does not imply backup/restore wrapper support.

Both wrappers need Docker/Compose, the built wallet image and an existing
selected wallet volume. Match your deployment's `COMPOSE_FILE`,
`COMPOSE_PROJECT_NAME`, `ECD_WALLET_VOLUME` and `NETWORK`, including any additional
mode files. The helper image is selected by host `IMAGE`, then
`ELECTRON_CASH_IMAGE`, then `electron-cash:<EC_VERSION>`; it does not automatically
select `ECD_HW_IMAGE`. For Ledger backups, set host `IMAGE` to your built hardware
image as well as keeping the GUI/hardware files. `BACKUP_DIR` and `IMAGE` are
wrapper environment variables: set them in the terminal, not just in `.env`.
Do not let another deployment write the same wallet volume.

### Make a backup

1. Finish current wallet operations. In the repository root, choose a new archive
   name (letters, digits, `.`, `_`, `-`; no paths or `..`):

   ```bash
   ./scripts/backup.sh backup wallet-copy
   ```

   Windows PowerShell alternative:

   ```powershell
   .\scripts\backup.ps1 backup wallet-copy
   ```

2. Enter and confirm a strong archive password at the prompts. Do not pass it
   as an argument or environment variable. The script temporarily stops Electron
   Cash if running to make a consistent copy, then returns that service to its
   prior state on success. If it was stopped, it stays stopped. Check any reported
   restart failure: a completed archive does not imply the service restarted.
3. Check the success message and retain **`backups/wallet-copy.ecd.gpg`**.
   `BACKUP_DIR` changes the destination; use an absolute host directory path.
   An existing archive is not overwritten.
   Copy the encrypted file off-host; it uses AES-256 GPG encryption and includes
   the selected network, manifest and file hashes.

For a headless Linux deployment, for example, select the same mode files:

```bash
COMPOSE_FILE=docker-compose.yml:docker-compose.headless.yml ./scripts/backup.sh backup wallet-copy
```

On Windows, set `COMPOSE_FILE` in the environment using Windows' `;` file-list
separator and `COMPOSE_PROJECT_NAME` to match the deployment before using the
PowerShell wrapper. For other modes, retain their complete file list too.

For example, for a headless project named `my-wallet` in Windows PowerShell:

```powershell
$env:COMPOSE_FILE = 'docker-compose.yml;docker-compose.headless.yml'
$env:COMPOSE_PROJECT_NAME = 'my-wallet'
.\scripts\backup.ps1 backup wallet-copy
```

Use your actual project name, not the example, and retain these selections for
restore. They remain set in that terminal; open a fresh terminal or clear them
before operating on another installation.

### Restore an archive

**Restoring replaces the selected network's current wallet state.** It is not
the next step after every backup. First rehearse in an isolated disposable
deployment with a clean, initialized volume and no real wallet; ensure its
volume, project, images and ports do not overlap your live setup. Keep the same
archive network and an image with the **same Electron Cash version recorded
in the archive**. The scripts validate the
archive format, network and hashes; they are not arbitrary wallet-format converters.

1. Preserve a current backup before replacing existing data. Put the archive in
   `backups/` (or the chosen `BACKUP_DIR`) and confirm the deployment, volume,
   network and mode settings. Other networks' data will be preserved.
2. Run only the restore command for your host:

   ```bash
   ./scripts/backup.sh restore wallet-copy
   ```

   Windows PowerShell alternative:

   ```powershell
   .\scripts\backup.ps1 restore wallet-copy
   ```

3. Read the overwrite warning, confirm only if the target is correct, and enter
   the archive password. Cancellation, a wrong password, an invalid archive or
   network mismatch must leave existing wallet data untouched. The script
   validates before replacement and saves the current volume for rollback.
4. Check the result. If Electron Cash was running, the wrapper restarts it and
   checks startup/health. **If it was stopped, it remains stopped**; there is no
   forced startup/health test in that case. Start the intended mode yourself when
   ready, using `docker compose up -d` with the same project and mode files, and
   check the recovered wallet and metadata in Electron Cash. A wallet
   encryption password may still be required after decrypting the archive.

If replacement or subsequent startup fails, the wrapper attempts to restore
the saved state. If rollback cannot finish, it preserves the recovery volume
and pending record and reports failure. Preserve both and sanitized logs;
do not delete volumes, discard the pending record or blindly repeat replacement.
The wrapper checks for an interrupted restore on its next invocation and
attempts recovery before continuing. A successful archive creation alone does
not prove you can recover it.

## Other access modes

Use these routes when you need remote access, a native window, hardware or
automation. Complete `.env` setup and build the required images first. Before
switching modes, remove the current mode's containers with its normal `down`
(without `--volumes`), then start the new mode. Keep the full Compose file list
for start, stop, backup and upgrade. Never run two wallet processes against the
same volume or enable the web-service profiles in a native/headless deployment.

### Local and protected remote access

Defaults are `CADDY_EDGE_BIND=127.0.0.1`, HTTP port 80, HTTPS port 443 and
`CADDY_SITE_ADDRESS=localhost`. Local HTTP does not redirect; local HTTPS uses
Caddy's internal certificate authority and needs appropriate browser/OS trust.
Use `CADDY_HTTP_HOST_PORT` / `CADDY_HTTPS_HOST_PORT` for host port conflicts.
There is no supported direct `NOVNC_BIND`/`NOVNC_HOST_PORT` mapping.

Remote access requires domain, firewall and certificate administration:

1. Use a strong unique `BASIC_AUTH_PASSWORD`; keep session protection and fail2ban.
2. Set `CADDY_SITE_ADDRESS=wallet.example.com` (domain only),
   `CADDY_TLS_MODE=auto`, `CADDY_EDGE_BIND=0.0.0.0` and host ports 80/443.
3. Configure the domain's DNS A/AAAA records and inbound TCP 80/443 yourself.
   Public certificate issuance depends on DNS, reachability and the certificate
   authority. Recreate the project after the configuration change.
4. From an independent client, verify valid HTTPS and HTTP-to-HTTPS redirect,
   rejection of unauthenticated assets/WebSocket connections, and temporary
   fail2ban blocking without blocking another client.
5. Never publish internal VNC 5900/noVNC 6080, or unauthenticated RPC. Keep RPC
   loopback-only. Do not disable certificate verification or casually change
   trusted-proxy ranges; arbitrary forwarded headers do not establish client identity.

Caddy checks the web session before forwarding protected desktop traffic. The
historical Basic Auth terminology does not mean a username or browser-native
Basic Auth dialog is needed. Fail2ban defaults to five failures in 600 seconds
and a 3600-second ban; loopback is ignored. Passive GUI-status 401s are not
password guesses. Through supported proxies, blocking may be logical in Caddy
rather than a packet-level DROP of the final client's IP.

### Native GUI and Ledger

**Linux native window.** Use a local authenticated X11/XWayland desktop.
`DISPLAY` identifies the display; Xauthority is the private cookie that permits
access. Keep the host cookie in its normal location (`XAUTHORITY` when set).
The helper copies it into a private read-only runtime volume. Do not use
`xhost +` or change host cookie ownership. After building the base images:

```bash
test -n "$DISPLAY" &&
docker compose -f docker-compose.yml -f docker-compose.gui.yml up -d
```

You should get a native Electron Cash window, without noVNC/web services.
Stop with the same files before returning to browser mode:

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml down
```

**macOS native window.** Install/start Docker Desktop and XQuartz. The launcher
requires Compose **2.24.4+** for its generated `!override` file. It also needs
host Python 3 and XQuartz's `xauth` available in your shell's PATH
(normally `/opt/X11/bin`), alongside the standard macOS tools. Remove the current
mode's containers/network with its normal `down`, without deleting volumes:
the launcher refuses a project that already owns these resources.
On **Intel**, after building the base wallet image, run:

```bash
bash scripts/mac-gui.sh
```

On **Apple Silicon**, explicitly select the supported image platforms: wallet
`linux/amd64` under emulation and Tor `linux/arm64`. The launcher accepts a
validated `ECD_PLATFORM_OVERRIDE` file; it does not automatically select these
platforms. This POSIX example creates a temporary file, builds the matching
wallet image, runs the launcher and removes the temporary file on exit:

```bash
(
  MAC_PLATFORM_FILE="$(mktemp "${TMPDIR:-/tmp}/ecd-mac-platform.XXXXXXXX")" || exit 1
  trap 'rm -f "$MAC_PLATFORM_FILE"' EXIT
  python3 - "$MAC_PLATFORM_FILE" <<'PY' || exit 1
import json, sys
with open(sys.argv[1], "w") as target:
    json.dump({"services": {
        "electron-cash": {"platform": "linux/amd64"},
        "tor-proxy": {"platform": "linux/arm64"}
    }}, target)
PY
  DISPLAY="${DISPLAY:-:0}" docker compose -f docker-compose.yml -f docker-compose.gui.yml -f "$MAC_PLATFORM_FILE" build electron-cash || exit 1
  ECD_PLATFORM_OVERRIDE="$MAC_PLATFORM_FILE" bash scripts/mac-gui.sh
)
```

The launcher manages temporary display cookies/listener settings and restores
prior settings on exit. Finish or cancel assistants and close the last wallet
window to end the foreground launcher;
it removes its containers while keeping wallet volumes. This is local desktop
access, not public X11. Tor's native arm64 image avoids its amd64-emulation
seccomp limitations; do not disable the sandbox to work around them.
See [platform validation](platform-validation.md) for observed configurations,
native architecture boundaries and maintainer SSH-display instructions.

**Ledger.** Use only native Linux Docker Engine, the GUI file and
`docker-compose.hw.yml`. Set `HW_USB_GID` to the group owning the host Ledger USB
node and arrange the required host device permissions; see
[platform validation](platform-validation.md#ledger--native-linux).

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml -f docker-compose.hw.yml build electron-cash
docker compose -f docker-compose.yml -f docker-compose.gui.yml -f docker-compose.hw.yml up -d
```

Unlock the device and open its BCH app **on the device**. Never type its PIN or
seed into the browser, terminal or logs. Only the hardware wallet image gets
USB access; it does not need a privileged container. The backend filters Ledger
identifiers, but the additional file exposes the host Linux USB bus, not just
one device. Keep unrelated sensitive USB devices off that path. There is no
claim of all-model compatibility, other hardware-wallet backends, Docker
Desktop Ledger support or transaction-signing certification.

### Headless and RPC

Headless runs the daemon without a desktop, for operators comfortable with
wallet CLI use. After building, start it and wait for health/readiness:

```bash
docker compose -f docker-compose.yml -f docker-compose.headless.yml up -d --wait
docker compose -f docker-compose.yml -f docker-compose.headless.yml exec --user 10001:10001 electron-cash /opt/electroncash-venv/bin/electron-cash daemon status
```

For a non-mainnet network add its CLI flag, such as `--chipnet`, before
`daemon status`. No Xvfb/Openbox/RFB/websockify is started. The base configuration
still requires `BASIC_AUTH_PASSWORD` for Compose interpolation, although the web
services do not start. Real encrypted wallets require operator load/unlock;
`WALLET_AUTO_CREATE` is a disposable Chipnet-only testing facility, not a
production setup method. Wait for readiness before CLI operations: premature
commands can write upstream configuration during initialization. Startup and
health checks themselves use a read-only local daemon ping.

JSON-RPC lets automation control the wallet. It is disabled by default
(`JSONRPC_ENABLED=false`) and needs **separate**, non-empty `JSONRPC_USER` and
`JSONRPC_PASSWORD` in `.env`. Only the explicit RPC file enables and publishes it:

```bash
docker compose -f docker-compose.yml -f docker-compose.headless.yml -f docker-compose.rpc.yml up -d
```

The host binding is `127.0.0.1:50001`; `JSONRPC_HOST_PORT` changes the host port
and `JSONRPC_PORT` the internal port. The internal daemon also requires password
authentication. Keep credentials out of URLs, shell history and shared logs.
Native GUI and RPC files cannot be combined. Never expose signing/automation
authority publicly; stop with the same complete file list when finished.

## Troubleshooting and upgrade

### Upgrade without losing wallet data

1. Make an encrypted backup and verify recovery before upgrading.
2. Obtain the intended reviewed version. Compare the new `.env.example` with
   your `.env` without overwriting secrets; check version/hash entries and image
   choices. Inspect resolved Compose locally, redacting secrets before sharing.
3. Finish pending wallet operations and stop the current deployment with
   `docker compose stop`, using its full mode file list. Preserve `.env`, wallet
   data and persistent volumes. Rebuild/recreate with
   exactly the **same Compose project and mode files**. For the default mode:

   ```bash
   docker compose --env-file .env config --images
   docker compose build --pull
   docker compose up -d
   ```

4. Open the wallet, check the network and data, and log in again if required.

The supported v0.4 → v1.0 path requires **no wallet-file conversion**. Existing
plugin/Fusion preferences and the ownership marker remain; no intermediate
release exists. Changes to environment settings take effect on recreation.
The upgrade from memory-only web authentication requires loading the new
client and one fresh login: lost memory-only sessions cannot be recovered.
Never use `down --volumes` to upgrade.

### Diagnose by symptom

Start with `docker compose ps` and `docker compose logs`, including the same
mode files as your deployment. Share only sanitized logs, never `.env`, seeds,
wallet files, authentication databases or credentials.

| Symptom | First check and non-destructive next step |
|---|---|
| Login rejected or access denied | Check hostname, cookie/session expiry and `.env` password escaping (`$$`). After changing settings recreate with `up -d`; log in again. A 403 can be an origin-policy error, not a wrong password. |
| Page cannot connect | Check service readiness and the chosen HTTP port. Change edge host ports for conflicts; do not publish noVNC directly. |
| Session-ended message or blank desktop | If the last window/assistant ended, use `up -d` and keep the tab open. Otherwise inspect wallet logs for a crash or startup error; do not delete data. |
| Tor healthy but wallet offline | Check Tor logs and external network/server reachability. Local SOCKS readiness does not prove Internet connectivity. Never share seeds to diagnose it. |
| Empty wallet or wrong network | Verify `NETWORK` and inherited shell variables; select the intended network and recreate before considering restoration. Other networks have separate state. |
| Backup or restore fails | Check selected volume/network/mode, archive path and password prompts. Retain any pending recovery record/snapshot; follow the reported rollback result rather than deleting volumes. |
| Native window does not open | On Linux check `DISPLAY`, Xauthority and local X11/XWayland. On macOS check Docker Desktop, XQuartz and launcher output; use the platform reference, not `xhost +` or disabled seccomp. |
| Keyboard layout or shortcuts fail | Focus the field, use noVNC extra keys/virtual input, or choose native mode; see [browser keyboard](#browser-keyboard). |
| Invalid language/theme/Fusion/network setting | Correct `.env` and recreate. Startup rejects invalid values rather than silently choosing another setting. |

### Reset only web authentication

Use this advanced recovery step only after identifying a problem with web
session storage. If it is corrupt, unreadable, unwritable or unsupported,
authentication refuses access rather than replacing it or falling back to memory.
Wallet data is separate. See [Security](../SECURITY.md#web-access-and-recovery-controls).

In a POSIX shell with host Python 3, resolve and inspect the **exact** auth volume
for this deployment, stopping/removing its containers without deleting volumes:

```bash
AUTH_VOLUME="$(docker compose config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["volumes"]["auth-session-data"]["name"])')"
docker compose down
docker volume inspect "$AUTH_VOLUME"
```

Verify the inspected name belongs only to this deployment's authentication
storage. Only then remove that exact volume and recreate:

```bash
docker volume rm "$AUTH_VOLUME"
docker compose up -d
```

Old sessions will need login. Do not remove wallet/Tor volumes or use
`down --volumes`. Keep authentication databases out of logs and shared bundles.

## Try it without funds

Explore the browser desktop with a separate disposable source copy and a new,
unfunded Chipnet wallet. Never import a real wallet, seed or private keys;
do not send funds or publish a funding address.

1. Follow the [prerequisites](#choose-your-setup). **Before building or starting**,
   create `.env` only if absent in the disposable copy and set a unique
   `BASIC_AUTH_PASSWORD` (`$$` for literal `$`), `NETWORK=chipnet`,
   `ECD_WALLET_VOLUME=ecd-v1-demo-wallet` and `ECD_TOR_VOLUME=ecd-v1-demo-tor`.
   Keep `MODE=novnc`, `USE_TOR=true`, `CASHFUSION_AUTO_FUSE=false`,
   `WALLET_AUTO_CREATE=false` and `JSONRPC_ENABLED=false`. Use only the base
   Compose file, without native/RPC files.
2. Keep `CADDY_EDGE_BIND=127.0.0.1` and `CADDY_SITE_ADDRESS=localhost`. Choose
   unused host ports, for example `CADDY_HTTP_HOST_PORT=18080` and
   `CADDY_HTTPS_HOST_PORT=18443`. Give all five image outputs unused demo-only
   local tags via `ELECTRON_CASH_IMAGE`, `TOR_IMAGE`, `AUTH_SESSION_IMAGE`,
   `CADDY_IMAGE` and `FAIL2BAN_IMAGE`.
3. Confirm project `ecd-v1-demo`, both explicit volume names, all project-prefixed
   volumes, image tags and ports are unused; choose other names/ports if occupied.
   Use a shell without inherited Compose/runtime settings: shell variables
   override `.env`. Inspect the resolved model locally (it includes the password;
   do not share it). Confirm Chipnet, loopback ports and disposable resources only:

```bash
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo config
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo build --pull
docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo up -d
```

Open `http://127.0.0.1:18080/` (adjust for your chosen port), log in and create
the new Chipnet wallet interactively. Try the keyboard, language/theme and
closing/reopening the application. Repeat the same scoped `up -d` command
for restart or recreation. Keep seeds and passwords private. External test
services may be unavailable; inspecting CashFusion settings does not demonstrate
fusion on Chipnet, and **this trial must not start a round**.

Stop with `docker compose --env-file .env -f docker-compose.yml -p ecd-v1-demo down`.
Only after confirming that **every resolved volume belongs exclusively to this
disposable trial**, repeat that command with `--volumes` to erase its data.
Keep the same `.env`, Compose file and project. Never apply this cleanup to real
wallet resources or use global Docker prune.

## Technical options and limits

Use this section when you need precise configuration or session behaviour.
The everyday path needs only the settings in the quick start.

### Browser keyboard

noVNC forwards ordinary text and editing keys, but the browser or operating
system can intercept shortcuts such as switching applications or focusing the
address bar. Use its extra-key buttons for Ctrl/Alt and Ctrl-Alt-Delete. Check
focus after switching windows and release stuck modifiers after focus loss.

The keyboard button requests your device/browser's on-screen keyboard through
a hidden text field. It is not a clickable keyboard grid; desktop browsers may
show no on-screen keyboard. Text goes to the remote field; special keys use the
toolbar. Layouts, dead keys and input methods (IME) vary. Try virtual text input
or a supported native window if your layout does not work well. Never paste a
seed into the browser clipboard. A virtual keyboard does not protect against
screen capture or every keylogger. Support covers exercised browser/device
combinations, not universal IME compatibility; these controls do not apply to
native or headless mode.

### Networks and lifecycle

`NETWORK=mainnet` is the default for real BCH. Electron Cash 4.4.6 supports
exactly `mainnet`, `testnet`, `testnet4`, `scalenet`, `chipnet` and `regtest`;
empty/unknown values stop startup. Set `NETWORK` in `.env` and recreate. For
a temporary selection in Bash only:

```bash
NETWORK=chipnet docker compose up -d
```

Repeat that selection for subsequent operations, or save it in `.env` to avoid
accidentally returning to mainnet. Mainnet uses the volume root; other networks
have separate subdirectories for wallets, configuration and external plugin
state. Additional Compose files choose capabilities, not networks. Remove
obsolete `CHIPNET=true` and `TESTNET4=true`; do not override networks, wallet paths
or GUI language through `ELECTRONCASH_ARGS` (use `EC_LANGUAGE` for new configs
and Electron Cash Settings for existing configs).
Test servers may be unavailable. Regtest requires a reachable compatible
Electrum server; this deployment does not include a BCH full node.

### Web session reference

- `BASIC_AUTH_PASSWORD` must be non-empty, at most 256 characters, contain no
  newline, carriage return or NUL, and not begin with the placeholder `CHANGE_ME`.
  These are acceptance limits, not a password-strength check.
- Temporary cookies have no Max-Age/Expires; their server session expires
  30 minutes after login. Remembered cookies have a Max-Age and server deadline
  of 30 days. Activity and passive probes do not renew either deadline.
- The application does not save the login password in localStorage,
  sessionStorage or URLs. Authentication uses an HttpOnly, SameSite=Strict HTTP
  cookie, with Secure over HTTPS. Browser password-manager autofill is permitted;
  this is not a promise that your browser stores no credentials or traces.
- Valid sessions survive restart, recreation and down/up only while the browser
  cookie, dedicated auth volume and original deadline remain. Recreating with
  the same password preserves them. Changing it and recreating revokes them;
  changing back does not revive old sessions.
- Visiting `/` revokes a temporary session; a valid remembered session redirects
  to the desktop. A same-origin POST to `/auth/logout` revokes either kind.
  Other tabs' status/recovery checks do not log you out. Network errors, 5xx and
  403 do not prove expiry; an explicit 401 returns you to login.
- Wallet deletion, backup and restore neither copy nor reset web sessions.
  Server storage keeps a hash of each opaque session token, not the reusable token;
  detailed SQLite, credential-generation and compromise limits are in
  [Security](../SECURITY.md#web-access-and-recovery-controls).

### Plugin provenance

`plugins.json` records bundled plugin sources, versions, source/ZIP SHA-256
hashes and activation. Builds reject hash mismatches and startup rechecks the
bundled artifacts. There is no open plugin registry or runtime plugin download.
To change a plugin, review its source, deliberately update the version/hash
entries and rebuild. Matching hashes identifies the declared files; it does
not establish that arbitrary plugin code is safe.

### CashFusion controls

These initial defaults apply only to missing wallet preferences:

| Variable | Default / meaning |
|---|---|
| `CASHFUSION_FUSION_MODE` | `custom` |
| `CASHFUSION_FUSE_DEPTH` | `3` rounds; `0` means unlimited in Electron Cash |
| `CASHFUSION_SELF_FUSE_PLAYERS` | `1`, no self-fusing |
| `CASHFUSION_SELECTOR_MODE` | `count`; alternatives `size`, `fraction` |
| `CASHFUSION_SELECTOR_COUNT` | `10` target coins |
| `CASHFUSION_SELECTOR_SIZE_BCH` | `0.0001` BCH for size selection |
| `CASHFUSION_SELECTOR_FRACTION` | `1.0`, range 0.0–1.0, for fraction selection |
| `CASHFUSION_QUEUED_AUTOFUSE` | `4` |
| `CASHFUSION_AUTOFUSE_CONFIRMED_ONLY` | `true` |

The initial profile uses `custom` mode, one participant from the wallet per
round (no self-fusing), and automatic participation only when all wallet coins
are confirmed. The queue and selection settings do not enable automatic fusion
while `CASHFUSION_AUTO_FUSE=false`. Supported modes are `normal`, `consolidate`,
`fan-out` and `custom`; depth is 0–10, participants 1–2, count 10–9999 and queue
1–10. Size selection must be at least 0.0001 BCH with at most eight decimal
places; fraction must be 0.0–1.0. Use a decimal point in `.env`, regardless of
the GUI language.

Separate deployment controls apply to both manual and automatic fusion:

- `CASHFUSION_FEE_BUDGET=0` adds no fee cap. A positive integer caps the source
  wallet's attributable miner-fee contribution per round, in satoshis, checked
  on the final transaction before signing. It is not a cumulative spending budget.
- `CASHFUSION_MIN_UTXO=1000` excludes inputs below 1,000 satoshis; equality is
  allowed, subject to normal eligibility. Zero adds no threshold. If an input is
  too small, its whole native address bucket is excluded, preserving linkage
  and native frozen-coin/token/confirmation exclusions.
- A positive cap rejects raw/mixed source provenance or multiple players from
  the same wallet when that wallet's contribution cannot be safely bounded.
  Limits bind to each fusion object; retries recheck the final transaction,
  without a shared spending database. Stored wallet preferences cannot disable them.
- Both values must be integers from 0 to 2,100,000,000,000,000. Empty, negative,
  fractional, malformed or larger values reject startup. Recreate after editing
  `.env`. These deployment controls are hash-bound to Electron Cash 4.4.6,
  not upstream preferences. `CASHFUSION_TARGET` is unsupported; use the native
  count/size/fraction selectors.

### Images, storage and security limits

[`.env.example`](../.env.example) is the configuration reference. It fixes
Electron Cash, noVNC, Tor and Caddy with source identities/hashes. `ELECTRON_CASH_IMAGE`, `TOR_IMAGE`, `AUTH_SESSION_IMAGE`, `CADDY_IMAGE` and
`FAIL2BAN_IMAGE` optionally name local build outputs; gateway defaults use local
v1.0 tags. Rebuild rather than substituting unverified remote images.

Wallet processes run as UID/GID 10001:10001. Startup rejects unsafe ownership
or symbolic links rather than silently repairing unknown contents; writable
persistent wallet state remains under `/home/electroncash/.electron-cash`.
Web sessions use a separate project-owned `auth-session-data` volume mounted
only into auth-session at `/auth-data/` (database `/auth-data/sessions.sqlite`).
GUI lifecycle notification needs no Docker socket, host PID access or additional
capabilities. Its passive recovery observer uses a 3-second request timeout,
5-second ended-state interval and outage backoff capped at 30 seconds; web
services have up to six seconds to notify the loaded page before stopping.

Read-only roots, bounded temporary storage/resources, scoped capabilities,
non-root wallet processes, web sessions/TLS/fail2ban and encrypted backups are
layers of protection, **not an audit or absolute security guarantee**. A
compromised host or Docker administrator can read wallet data. The unpatched
`ecdsa` advisory **CVE-2024-23342** remains; private operations require the
verified native BCH secp256k1 backend, not a claim of an upstream fix.

Read [Security](../SECURITY.md) and [platform validation](platform-validation.md)
for detailed limits and observed platform boundaries. Maintainer validation
commands and evidence are in [README's validation section](../README.md#validation);
synthetic checks do not certify all macOS systems, hardware models, architectures
or public deployments.
