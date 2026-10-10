# Platform validation

Electron Cash Docker uses automated regression for routine changes and
occasional, opt-in real-host checks to prove platform-specific boundaries.
Automated checks do not require a physical Mac, desktop display, or Ledger and
do not claim a physical-host result.

## Automated maintainer regression

Run the lightweight checks with:

```bash
./scripts/ci.sh fast
```

The provider-independent suite is available separately with
`./scripts/ci.sh gate`. It builds isolated validation images and requires every
registered acceptance test to pass. Coverage includes an ordinary cold public Compose
first-run, pinned state/backup upgrade fixtures, authenticated Linux GUI
Compose on external Xvfb, XQuartz launcher mocks, and a synthetic Ledger
backend. The first-run uses default image names and the selected default
Buildx builder; a builder failure is recorded as infrastructure failure rather
than being substituted with a separate builder. These tests do not certify a
physical display, Mac, or Ledger.

## User-run Compose paths

These commands exercise the product directly after following the README Quick
Start and configuring `.env` with a real `BASIC_AUTH_PASSWORD`. They do not run
the maintainer acceptance suite.

### Linux X11 desktop

From a local authenticated Linux X11/XWayland session, keep the host
`$DISPLAY`, `$HOME/.Xauthority` (or `$XAUTHORITY`), and `/tmp/.X11-unix` intact.
Compose checks the selected cookie and socket, then prepares a private
UID-10001 cookie copy for the wallet container:

```bash
test -n "${DISPLAY:-}" &&
docker compose -f docker-compose.yml -f docker-compose.gui.yml up -d
```

The source authority file and socket are mounted read-only; do not create a
world-readable cookie, `chown` the host file, or use `xhost +`. To return to the
browser deployment:

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml down &&
docker compose up -d
```

For an SSH-forwarded display, use the maintainer `linux-x11` runner below; it
relays the authenticated display through a task-owned Unix socket.

### Ledger on native Linux Docker Engine

This user path requires an unlocked supported Ledger with the BCH app open and
host udev permissions for its USB device node. Obtain the exact `/dev/bus/usb`
node from `lsusb`, then derive its group rather than copying a sample GID:

```bash
if read -r -p 'Ledger USB node (/dev/bus/usb/BBB/DDD): ' LEDGER_NODE &&
   [[ "$LEDGER_NODE" =~ ^/dev/bus/usb/[0-9]{3}/[0-9]{3}$ ]] &&
   test -c "$LEDGER_NODE" && test -n "${DISPLAY:-}" &&
   HW_USB_GID=$(stat -c '%g' "$LEDGER_NODE") &&
   [[ "$HW_USB_GID" =~ ^[0-9]+$ ]]; then
  export HW_USB_GID
  docker compose -f docker-compose.yml -f docker-compose.gui.yml \
    -f docker-compose.hw.yml up -d
else
  printf '%s\n' 'Ledger not started: check USB node, group and DISPLAY.' >&2
fi
```

Compose automatically builds the required Ledger support. This Linux-only,
opt-in overlay maps the host `/dev/bus/usb` bus to the wallet, with USB device
cgroup access (`c 189:* rw`); other services receive no USB access. The backend
filters Ledger IDs, but the selected node's `HW_USB_GID` grants group permissions,
not bus isolation. Do not attach unrelated sensitive USB devices to that path.
Unlock/open the BCH app on-device; never enter PIN/seed in the terminal or logs.
To stop Ledger mode, use the same three files with `down` instead of `up -d`.

## Opt-in maintainer platform checks

Invoke only the check for the host you are validating:

```bash
./scripts/ci.sh platform-run linux-x11
./scripts/ci.sh platform-run mac-xquartz
HW_USB_GID=... ./scripts/ci.sh platform-run ledger-linux
```

The runners check prerequisites, build only the images required by the
scenario when needed, use the pinned `linux/amd64` application image, create
disposable task-owned Chipnet state, and clean up resources claimed by that
run. They do not require the full gate, use a personal wallet or seed, or
approve a transaction. Verified application and Tor image artifacts are
retained; runners do not globally prune or alter unrelated Docker resources.
The interactive `platform-run mac-xquartz` check waits for operator inspection;
Apple Silicon has the unattended canonical command documented below.

Canonical unattended checks retain safe evidence and SHA-256 manifests outside
the repository. Source/build-input fingerprints and immutable image IDs bind
each result to its tested candidate; retained PASS results are not guarantees
for the current checkout. Platform-specific evidence and verifier details follow.

### Linux desktop / X11

The canonical **unattended local Linux X11 integration** command is:

```bash
./scripts/ci.sh linux-x11
```

This target is independent of `gate`. Its backend preference is
an authenticated usable local Xorg/XWayland session, task-owned Xorg with
`modesetting` on usable DRM/KMS, then genuine headless Xorg with the `dummy`
video driver. A known wedged DRM device is skipped. Temporary servers use a
dynamically free display, private Xauthority and `-nolisten tcp`. The dummy
backend uses a separate task-owned seat, disables automatic GPU/device binding,
and provides a 1280×800 depth-24 screen without probing QXL. Xvfb, forwarded
displays and synthetic Qt backends cannot satisfy it. It uses the native GUI
overlay and production `x11-authority` service.
Disposable Chipnet wallet/config volumes and a unique Compose project isolate
the run. A mapped Electron Cash window must match the non-root container Qt
process; real X11 File-menu input must map/dismiss a popup; native Ctrl+Q must
exit with zero status and no crash/restart. Cleanup runs on failure as well.

Prerequisites: local Docker Engine/Compose, `x11-utils` (`xdpyinfo`, `xwininfo`,
`xprop`, `xwd`), `xauth`, `xdotool`, and, for temporary Xorg, `xserver-xorg-core`
plus `xserver-xorg-video-dummy` for the independent headless fallback
and noninteractive sudo. No desktop environment or window manager is needed.
These are test-host packages, not product runtime dependencies. Xvfb may be
installed for other uses, but is never an acceptance backend.

The test automatically reuses local images only after checking saved build
inputs/configuration/modes and immutable image IDs. Proofs are discovered under
`~/.local/state/electron-cash-docker/` (`focused-images*.json`, `image-proof.json`);
`ECD_X11_IMAGE_PROOF` can select one explicitly. Missing/mismatched images are
built individually from the current inputs. No old-image/new-source PASS is
allowed. Safe JSON results and a SHA-256 manifest are retained automatically in
`~/.local/state/electron-cash-docker/v<VERSION>-linux-x11-<UTC-id>/`.
`--evidence-dir` can select a new external directory. Temporary configuration
and cookies live in a task-owned home-backed directory to avoid host `/tmp`
quotas and are removed. Cookies, wallet content and raw application logs are
not retained. Focused harness checks: `python3 tests/test_linux_x11_harness.py`.

Xorg dummy validates native-X11 protocol/application integration, not GPU,
DRM, hardware acceleration or a physical monitor.

The `platform-run linux-x11` interactive/SSH-capable runner has a separate
observation boundary:

Run on native Linux Docker Engine with an authenticated X11 display and
Xauthority available. Use a real desktop display; Xvfb is automated regression
coverage, not a real-host display. The runner supports a local display or an
operator-authenticated SSH-forwarded display. For SSH forwarding, it relays the
live display through a task-owned Unix socket into the non-root GUI container;
it does not pass the host's `localhost` display into the container or expose a
TCP X11 port.

### macOS / XQuartz

The canonical **unattended real Apple Silicon** command is:

```bash
./scripts/ci.sh mac-apple-silicon
```

One execution validates the macOS/XQuartz desktop and supported Apple Silicon
runtime boundaries through `platform_runner.py`, production `mac-gui.sh`, and
the production Compose overlays. It requires a real Darwin/arm64 graphical host,
Docker Desktop, XQuartz and X11 tools (`xdotool` is the small test-only
interaction prerequisite; `brew install xdotool`). It is an explicit platform
target, outside the ordinary mandatory gate. No visual confirmation,
Accessibility permission, wallet funds or personal wallet is required.

The wallet remains `linux/amd64` under Desktop emulation; Tor is native
`linux/arm64`. Actual image IDs/platforms and in-container `uname` are checked.
A mapped Qt window must match the UID-10001 wrapper's container PID. Real X11
input must open and dismiss a wallet-process File-menu popup. Ctrl+Q must
remove the window and exit zero without crash or automatic restart. One
bounded production Compose relaunch verifies persisted disposable Chipnet
state, another mapped window, interaction, and a second normal Quit. Existing
user `.env` is not required: the runner selects `.env.example` with task-owned
exported runtime settings. Both paths still use the same supported launcher.

XQuartz TCP and XTEST preferences are changed only temporarily, with prior
presence/value and running/access state checked after cleanup. Session-only
authority files and task Docker resources are removed on success/failure.
Safe JSON evidence and command records live under
`~/.local/state/electron-cash-docker/v1.0-mac-apple-silicon-<UTC-id>/`.
An independent Python process reopens saved bytes and verifies artifact hashes,
current source/configuration/product-input hashes and modes, actual immutable
image IDs/platforms, required outcomes, and cleanup/restoration. To reverify:
`python3 tests/test_mac_apple_silicon.py --verify <evidence-directory>`.
Focused guards: `python3 tests/test_mac_apple_silicon_harness.py`.

The recorded physical PASS used Apple M4, macOS 26.7.1, Docker Desktop 4.94.0,
Docker Engine 29.8.2, Docker Compose 5.5.1 and XQuartz 2.8.6. This is one
observed configuration, not minimum requirements or all-platform certification.

The interactive `platform-run mac-xquartz` path also uses `mac-gui.sh` from a
graphical session, starting XQuartz if needed with MIT-MAGIC-COOKIE-1 cookies.
Its temporary TCP listener is only for Docker Desktop, never unrestricted
public X11 access or `xhost +`; no noVNC/Xvfb fallback is used. Intel Macs use
amd64 for both images. Apple Silicon's native arm64 Tor avoids amd64-emulation
seccomp limitations. Prior XQuartz running/TCP state is restored on exit,
failure or signal.

### Ledger / native Linux

The recorded physical Ledger check used a real Ledger Nano X over
USB. USB-over-IP was used solely to transport that physical USB connection to
the Linux Docker host. The physical run exercised the non-root production-backend
read-only BCH public path (firmware 2.4.5). It does not claim
transaction signing. This historical physical check is separate from the
virtual regression below.

Current-candidate Ledger compatibility is regression-tested automatically using
Speculos and the real Electron Cash Ledger plugin:

```bash
./scripts/ci.sh ledger-virtual
```

This explicit integration target is outside the default gate. It automatically
verifies/reuses the current wallet image's build inputs, starts official Ledger
Speculos **v0.27.1** (commit `23f17c58fe213dfa1b94b731953c2860731b8050`,
digest-pinned amd64 container), and loads official **Bitcoin Cash 2.4.12** from
`LedgerHQ/app-bitcoin-legacy` commit
`fdace8fa97901c5edb13997cfd47a2ef78db82c0`. The pinned builder compiles
`COIN=bitcoin_cash` for **Nano X / API 27** once; the verified ELF SHA-256 is
`de57955efcd503128aea96f60862b374af992df8569df063294da1be11f71337`.
Submodule, SDK, tool-image and artifact pins are maintained in
`tests/test_ledger_virtual.py`. Verified caches live outside the repository at
`~/.cache/ecd-ledger-virtual/`; the command needs Docker Engine/Compose, git,
Python 3 and network access only for missing pinned artifacts/build sources.

The public **BIP39_ABANDON_11_ABOUT_TEST_ONLY** fixture uses the standard eleven
`abandon` words plus `about`, empty passphrase and deterministic RNG. Never fund
or use this fixture outside testing. A test-only read-only mount supplies the
exact `btchip-python 0.1.32` / `hidapi 0.14.0.post4` HW dependencies to the
ordinary current wallet image. The only plugin injection replaces
`get_btchip_device` with a Speculos TCP APDU transport. Production plugin/client
initialization, btchip command construction, BCH feature detection, account
`m/44'/145'/0'` and leaf `/0/0` xpub operations remain real. Independent
BIP39/BIP32 CKDpriv, secp256k1 public-key, Base58Check and CashAddr calculations
must match device results; a fresh transport/client repeats the operations.
The bundled plugin source hash must equal the pinned upstream plugin. The
btchip Python-3 `str(bytearray)` address representation is compared exactly;
neither response bytes nor result-level methods are mocked.

The command retains candidate/image proof, pinned emulator/app/dependency
identities, APDU transcript, derivation/reconnect results and cleanup under
`~/.local/state/electron-cash-docker/v<VERSION>-ledger-virtual-<UTC-id>/`.
A separate verifier process reopens durable evidence and checks hashes and
mandatory PASS outcomes. `--evidence-dir` selects a new external directory.
Focused negative controls: `python3 tests/test_ledger_virtual_harness.py`.
The task-owned internal Docker network has no published host ports; emulator,
wallet process and temporary build/config data are removed on exit. Normal ECD
runtime and the production image do not depend on Speculos.

Virtual regression does not test signing or replace physical-device requirements.

The occasional physical smoke-test command remains available:

Ledger validation is limited to native Linux Docker Engine. Run with a
supported physical Ledger available to the Linux USB subsystem, unlocked with
the Bitcoin Cash app open, an authenticated X11 display, and device
permissions configured. Identify the selected Ledger node from `lsusb` and
derive `HW_USB_GID` from that exact node; do not copy an example GID:

```bash
if read -r -p 'Selected Ledger node from lsusb: ' LEDGER_NODE &&
   [[ "$LEDGER_NODE" =~ ^/dev/bus/usb/[0-9]{3}/[0-9]{3}$ ]] &&
   test -c "$LEDGER_NODE" && test -n "${DISPLAY:-}" &&
   HW_USB_GID=$(stat -c '%g' "$LEDGER_NODE") &&
   [[ "$HW_USB_GID" =~ ^[0-9]+$ ]]; then
  export HW_USB_GID
  ./scripts/ci.sh platform-run ledger-linux
else
  printf '%s\n' 'Ledger check not started: check USB node, group and DISPLAY.' >&2
fi
```

Configure host udev permissions so the selected node's group can read/write
the device. The runner uses the hardware-enabled image as the non-root wallet
user with the same bus mapping and group permissions described above.
Its Ledger probe is read-only: it checks firmware and the BCH public path and
discards the returned public key. USB enumeration alone is not a PASS.

## Results and cleanup

- `PASS` means that scenario's assertions completed.
- `FAIL` means the attempted check failed.
- `NOT RUN` means a required host prerequisite was unavailable; the command
  still exits nonzero.

All runners use ownership-scoped cleanup as described above, including on
failure; failed cleanup/restoration prevents PASS.

## Physical-validation applicability

Real physical checks are occasional platform proofs. A PASS remains applicable
across unrelated changes; routine changes are covered by automated regression.
Repeat only the physical test whose tested boundary is materially affected.
There is no age-only expiry and no blanket rerun because a source hash changed.
Historical artifact checksums establish integrity, not a match to today's
checkout. Applicability depends on the frozen original candidate identity and
source/image fingerprints. The Mac verifier also compares current source,
configuration, product-input hashes/modes and immutable images; a changed
checkout cannot pass that verification merely because historical checksums
match. Preserve original evidence and verifier checks; use a matching original
checkout for historical verification or generate fresh evidence for new inputs.

- macOS/XQuartz launcher, display, or authorization changes: repeat Mac.
- Docker Desktop/Engine, Compose, XQuartz, host, firmware, dependency or security
  boundary changes: rerun the tests for the affected boundary.
- Linux GUI, SSH X11 relay, or Xauthority changes: repeat Linux X11.
- Hardware Compose/device permissions/GID, USB transport, Ledger plugin,
  hidapi or Ledger dependency changes: review the materially affected physical
  boundary and consider repeating Ledger/Linux. Routine Ledger compatibility
  validation is `./scripts/ci.sh ledger-virtual`.
- Tor package-only changes: use Tor/runtime automated validation, including
  live routing; they do not require rerunning unrelated GUI or Ledger physical
  checks.

## Limits of retained physical observations

The Linux real-host observation used Linux Docker Engine with authenticated
remote X11 presentation; it was not a directly attached Linux-monitor test.
The Ledger USB-over-IP observation above did not prove direct USB attachment to
the Linux validation host. These are observation boundaries, not product requirements.
