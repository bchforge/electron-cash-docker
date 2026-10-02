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
first-run, the pinned v0.3-to-v0.4 state/backup upgrade, authenticated Linux GUI
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
test -n "$DISPLAY"
docker compose -f docker-compose.yml -f docker-compose.gui.yml up -d
```

The source authority file and socket are mounted read-only; do not create a
world-readable cookie, `chown` the host file, or use `xhost +`. To return to the
browser deployment:

```bash
docker compose -f docker-compose.yml -f docker-compose.gui.yml down
docker compose up -d
```

For an SSH-forwarded display, use the maintainer `linux-x11` runner below; it
relays the authenticated display through a task-owned Unix socket.

### Ledger on native Linux Docker Engine

This user path requires an unlocked supported Ledger with the BCH app open and
host udev permissions for its USB device node. Obtain the exact `/dev/bus/usb`
node from `lsusb`, then derive its group rather than copying a sample GID:

```bash
read -r -p 'Ledger USB node (/dev/bus/usb/BBB/DDD): ' LEDGER_NODE
test -c "$LEDGER_NODE"
export HW_USB_GID="$(stat -c '%g' "$LEDGER_NODE")"
docker compose -f docker-compose.yml -f docker-compose.gui.yml \
  -f docker-compose.hw.yml up -d
```

Compose automatically builds the required Ledger support. Only the wallet
receives USB node/group access. To stop Ledger mode, use the same three files
with `down` instead of `up -d`.

## Opt-in maintainer real-host checks

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
The Mac/XQuartz check waits for an operator to inspect and close the visible
Electron Cash window.

### Linux desktop / X11

Run on native Linux Docker Engine with an authenticated X11 display and
Xauthority available. Use a real desktop display; Xvfb is automated regression
coverage, not a real-host display. The runner supports a local display or an
operator-authenticated SSH-forwarded display. For SSH forwarding, it relays the
live display through a task-owned Unix socket into the non-root GUI container;
it does not pass the host's `localhost` display into the container or expose a
TCP X11 port.

### macOS / XQuartz

Run on macOS with Docker Desktop and XQuartz installed, from an interactive
graphical session. The runner starts XQuartz if needed, enables only the
temporary TCP listener required by Docker Desktop, and obtains XQuartz's
MIT-MAGIC-COOKIE-1 authorization before starting Electron Cash. It uses the
production `mac-gui.sh` path and the pinned `linux/amd64` application image; no
noVNC or Xvfb fallback is used. On Apple Silicon, the pinned Tor support
sidecar runs as native `linux/arm64` so Docker Desktop's amd64 emulation does
not prevent Tor's seccomp sandbox from loading; Intel Macs use amd64 for both
images. The runner restores the prior XQuartz running state and TCP preference
on exit, failure, or signal, and does not use `xhost +`.

### Ledger / native Linux

Ledger validation is limited to native Linux Docker Engine. Run with a
supported physical Ledger available to the Linux USB subsystem, unlocked with
the Bitcoin Cash app open, an authenticated X11 display, and device
permissions configured. Identify the selected Ledger node from `lsusb` and
derive `HW_USB_GID` from that exact node; do not copy an example GID:

```bash
read -r -p 'Selected Ledger node from lsusb: ' LEDGER_NODE
test -c "$LEDGER_NODE"
export HW_USB_GID="$(stat -c '%g' "$LEDGER_NODE")"
./scripts/ci.sh platform-run ledger-linux
```

Configure host udev permissions so the selected node's group can read/write
the device. The runner uses the hardware-enabled image as the non-root wallet
user and grants only the existing hardware overlay's USB node/group access.
Its Ledger probe is read-only: it checks firmware and the BCH public path and
discards the returned public key. USB enumeration alone is not a PASS.

## Results and cleanup

- `PASS` means that scenario's assertions completed.
- `FAIL` means the attempted check failed.
- `NOT RUN` means a required host prerequisite was unavailable; the command
  still exits nonzero.

Cleanup is ownership-scoped: a runner removes only disposable runtime
resources claimed by its current run. It retains verified image artifacts and
does not globally prune or alter foreign resources.

## Physical-validation applicability

Real physical checks are occasional platform proofs. A PASS remains applicable
across unrelated changes; routine changes are covered by automated regression.
Repeat only the physical test whose tested boundary is materially affected.
There is no age-only expiry and no blanket rerun because a source hash changed.

- macOS/XQuartz launcher, display, or authorization changes: repeat Mac.
- Linux GUI, SSH X11 relay, or Xauthority changes: repeat Linux X11.
- Hardware Compose/device permissions/GID, USB transport, Ledger backend, or
  Ledger dependency changes: repeat Ledger/Linux.
- Tor package-only changes: use Tor/runtime automated validation, including
  live routing; they do not require rerunning unrelated GUI or Ledger physical
  checks.

## Limits of retained physical observations

The retained Linux real-host observation used Linux Docker Engine with
authenticated SSH X11 presentation to Mac XQuartz; it was not a directly
attached Linux-monitor test. The retained Ledger observation used a physical
Ledger transported into Linux via USB-over-IP; it did not prove direct USB
attachment to `pro0` or transaction signing. These are observation boundaries,
not product requirements.
