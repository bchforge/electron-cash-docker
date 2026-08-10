# Tor Supply Chain

Electron Cash Docker v0.1.2 builds its Tor proxy locally from the official Tor
Project source release. The repository does not consume a third-party Tor
container image.

## Upstream And Pins

- Authority: [Tor source download page](https://www.torproject.org/download/tor/)
- Release announcement: [Tor 0.4.9.11](https://forum.torproject.org/t/security-release-0-4-9-11/21786)
- Source archive: `https://dist.torproject.org/tor-0.4.9.11.tar.gz`
- Signed checksum: `https://dist.torproject.org/tor-0.4.9.11.tar.gz.sha256sum`
- Signature: `https://dist.torproject.org/tor-0.4.9.11.tar.gz.sha256sum.asc`
- Tor version: `0.4.9.11`
- Source SHA-256: `2e6c1720118c812acf0079fd47cf91b6bfaba5d766c321c4d3d2a28d6a11a8ed`

The SHA-256 value is maintained in `.env.example` as `TOR_SOURCE_SHA256` and
is passed to the Tor Docker build as a required argument. The build downloads
the exact-version archive and checksum files from `dist.torproject.org`,
verifies the checksum file with `gpgv`, checks the expected signer fingerprints,
then verifies the archive against both the signed checksum and the configured
SHA-256 value.

## Release Authority

The Tor Project's [source verification instructions](https://support.torproject.org/little-t-tor/getting-started/verifying/)
list the release developers, fingerprints, and direct public-key links. The
repository stores the keys from those exact links; they are not selected from
an arbitrary keyserver search:

```bash
curl --fail --location --output tor-alexander.asc \
  https://keys.openpgp.org/vks/v1/by-fingerprint/1C1BC007A9F607AA8152C040BEA7B180B1491921
curl --fail --location --output tor-david.asc \
  https://keys.openpgp.org/vks/v1/by-fingerprint/B74417EDDF22AC9F9E90F49142E86A2A11F48D36
cat tor-alexander.asc tor-david.asc > tor-release-keys.asc
```

The resulting public-key export is stored in `docker/tor/tor-release-keys.asc`:

- David Goulet primary fingerprint:
  `B74417EDDF22AC9F9E90F49142E86A2A11F48D36`
- Alexander Faeroy primary fingerprint:
  `1C1BC007A9F607AA8152C040BEA7B180B1491921`
- Alexander Faeroy signing subkey used for this release:
  `514102454D0A87DB0767A1EBBE6A0531C18A9179`

Their full fingerprints were checked against the Tor Project verification page
before the keys were stored. The Docker build trusts only these repository
keys and fails if either expected `VALIDSIG` record is absent. It does not
consult the network or a keyserver during the build.

## Build Stages

`docker/tor/Dockerfile` has three meaningful stages:

1. `tor-verifier` downloads the source archive, signed checksum, and detached
   signature; it has no compiler and fails closed on missing, invalid, or
   unexpected verification data.
2. `tor-builder` compiles the verified Tor source with relay and directory
   authority modules disabled. Documentation generators, systemd integration,
   unit tests, and other build-only material are not included in the runtime.
3. `runtime` starts from the pinned Ubuntu 24.04 base image
   `ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea`,
   and copies only Tor, its required data files, the license, and the local
   SOCKS healthcheck.

## Runtime Boundary

The runtime user is UID/GID `10001:10001`. Compose adds `cap_drop: ALL`,
`no-new-privileges`, and a read-only root filesystem. Tor's only writable path
is `/var/lib/tor`, backed by the explicit Docker volume
`bchforge-electron-cash-tor-data`. This is Tor client state and is separate
from `bchforge-electron-cash-data`; Tor has no wallet-volume mount.

`docker/tor/torrc` enables only:

- SOCKS5 on `0.0.0.0:9050` for the private Compose network.
- Client-only operation and Tor's libseccomp sandbox.
- Foreground notice logging to Docker stdout.

There is no ControlPort, HTTP proxy, DNS proxy, transparent proxy, relay,
directory port, bridge relay, onion service, Nyx, or Lyrebird. Compose uses
`expose`, not `ports`, so 9050 is not published on the host. The healthcheck
performs a local SOCKS5 greeting against `127.0.0.1:9050`; it never contacts an
external website. End-to-end tests separately wait for Tor's `Bootstrapped
100%` message and verify a Tor-routed connection through the internal endpoint.

The Tor source `LICENSE` is copied into the runtime image at
`/usr/share/doc/tor/LICENSE`. It is the Tor Project's 3-clause BSD license plus
the bundled third-party notices. The repository's MIT license does not replace
those upstream obligations.

## Verification

```bash
docker compose --env-file .env.example config
docker compose --env-file .env.example build tor-proxy
docker run --rm --entrypoint /usr/local/bin/tor \
  bchforge/electron-cash-docker-tor:0.4.9.11 --version
docker compose --env-file .env.example up -d
docker compose --env-file .env.example logs tor-proxy
```

The negative build path must fail before compilation when the source pin is
wrong:

```bash
docker build --target tor-verifier \
  --build-arg TOR_VERSION=0.4.9.11 \
  --build-arg TOR_SOURCE_SHA256=0000000000000000000000000000000000000000000000000000000000000000 \
  ./docker/tor
```

Run `python3 tests/test_tor_proxy.py` for repository provenance checks,
negative verification, isolated hardening inspection, Tor bootstrap, SOCKS
validation, Electron Cash/noVNC startup, and restart/recreation coverage.

## Updating Tor

1. Select a stable release listed on the Tor Project download page.
2. Obtain its archive, `.sha256sum`, and `.sha256sum.asc` from
   `dist.torproject.org` and verify the checksum signature using the Tor
   Project's published signing-key fingerprints.
3. Update `TOR_VERSION` and `TOR_SOURCE_SHA256` in `.env.example`.
4. Update `docker/tor/tor-release-keys.asc` and the expected signer checks in
   `docker/tor/Dockerfile` if the release uses a new Tor Project authority.
5. Run the full Tor test suite and the existing persistence and CashFusion
   suites before changing any release documentation.

Do not replace the source archive with a community image, a floating URL, an
unsigned artifact, or a checksum calculated only from an untrusted download.

## Limitations

Tor covers only Electron Cash traffic explicitly configured to use
`tor-proxy:9050`, including the CashFusion plugin. It does not protect the
browser, Docker host, wallet volume, or unrelated applications. A working
SOCKS listener and a successful Tor circuit do not protect the wallet from a
compromised host or unsafe wallet operations.
