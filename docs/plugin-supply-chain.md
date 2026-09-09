# Plugin Supply Chain

Electron Cash Docker v0.2 bundles one external plugin: Flipstarter Helper
v1.5.0. It is a reference plugin for the verified distribution mechanism, not an
open-ended plugin registry or marketplace.

## Build Boundary

[`plugins.json`](../plugins.json) records the repository source, exact archive
URL and release version, archive SHA-256, deterministic ZIP SHA-256, and
activation state. The Docker plugin-builder stage:

1. Fetches the exact HTTPS archive from the manifest.
2. Verifies the archive digest before extraction.
3. Checks the archive layout and plugin metadata identity.
4. Creates a deterministic ZIP with fixed timestamps and sorted entries.
5. Verifies the ZIP digest before the artifact enters the runtime image.

Missing, malformed, or mismatched hashes fail the build. There is no fallback to
latest, an alternate URL, or a cached artifact with a different digest.

## Runtime Boundary

The entrypoint verifies the image ZIP again before installing it in the
network-specific Electron Cash `external_plugins` directory. A mismatched
existing volume copy is removed before the verified artifact is atomically
installed. The runtime never downloads plugins. Electron Cash then discovers the
ZIP through its normal external-plugin loader and validates the plugin manifest.

The Flipstarter plugin declares Qt compatibility and is enabled by the trusted
manifest in GUI mode. It is not a headless command or protocol implementation.
The plugin does not change Electron Cash's wallet encryption or signing rules.

## Maintainer Update Procedure

The current v0.2 authority is the Flipstarter Helper project at
`https://gitlab.com/flipstarter/flipstarter-electron-cash`, using the reviewed
`v1.5.0` release archive. Updating the plugin requires all of the following,
in order:

1. Identify and review the intended upstream Flipstarter release/tag.
2. Update the manifest's project source, artifact URL, and release version.
3. Download or otherwise obtain that exact upstream archive.
4. Independently calculate and review the archive SHA-256.
5. Update `archive_sha256` with that reviewed digest.
6. Run the deterministic plugin packaging process with the production builder
   using a temporary output directory and `--generate-hashes`, for example
   `temporary=$(mktemp -d); PLUGIN_OUTPUT_DIR="$temporary" bash docker/plugins/build_plugins.sh --generate-hashes`.
7. Calculate and review the resulting deterministic ZIP SHA-256 from that
   temporary output.
8. Update `sha256` with that reviewed digest.
9. Run positive verification with the production builder again, without
   `--generate-hashes`, using `PLUGIN_OUTPUT_DIR="$temporary"`.
10. Run the deliberate wrong-hash negative verification in
    `tests/test_plugin_distribution.py`.
11. Run Electron Cash external-plugin discovery/load validation with
    `tests/test_flipstarter_plugin.py`.
12. Review the complete source and configuration diff before accepting the
    update.

Remove the temporary output directory after the review; do not make an ignored
repository-local ZIP a prerequisite for verification.

SHA-256 verification proves the identity and integrity of the downloaded and
packaged artifacts. It does not prove that the plugin code is vulnerability-free.
