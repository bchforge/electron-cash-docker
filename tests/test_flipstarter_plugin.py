#!/usr/bin/env python3
"""Acceptance checks for the pinned Flipstarter Electron Cash plugin."""

from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from test_support import electron_cash_image


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILE = ROOT / "plugins.json"
IMAGE = electron_cash_image()
PYTHON = "/opt/electroncash-venv/bin/python"


def run(command: list[str], *, timeout=120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def test_flipstarter_manifest_identity() -> None:
    document = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    assert document["plugins"][0] == {
        "package_name": "flipstarter",
        "source": "https://gitlab.com/flipstarter/flipstarter-electron-cash",
        "artifact": "https://gitlab.com/flipstarter/flipstarter-electron-cash/-/archive/v1.5.0/flipstarter-electron-cash-v1.5.0.tar.gz",
        "version": "1.5",
        "archive_root": "flipstarter-electron-cash-v1.5.0",
        "archive_sha256": "d91e6a8e3203c93231ba1eb883103befb25159cea45362b1af83fc7037182723",
        "sha256": "e2da7ebbefaa1c9ad0ace7cc152b6eb54c0e992631c46d0c0eacb0bf71706f41",
        "enabled": True,
    }


def test_verified_flipstarter_artifact_is_discoverable() -> None:
    code = r'''
import hashlib
import json
import shutil
import tempfile
import zipfile
from pathlib import Path

from electroncash import SimpleConfig
from electroncash.plugins import Plugins

manifest = json.loads(Path("/preinstalled-plugins/plugins.json").read_text())
plugin = manifest["plugins"][0]
artifact = Path("/preinstalled-plugins") / f'{plugin["package_name"]}-{plugin["version"]}.zip'
assert hashlib.sha256(artifact.read_bytes()).hexdigest() == plugin["sha256"]
with zipfile.ZipFile(artifact) as archive:
    metadata = json.loads(archive.read("manifest.json"))
assert metadata["package_name"] == plugin["package_name"]
assert str(metadata["version"]) == plugin["version"]
assert "qt" in metadata["available_for"]

root = Path(tempfile.mkdtemp(prefix="flipstarter-loader-"))
external_plugins = root / "external_plugins"
external_plugins.mkdir()
shutil.copy(artifact, external_plugins / artifact.name)
config = SimpleConfig({
    "electron_cash_path": str(root),
    "use_external_flipstarter": True,
})
plugins = Plugins(config, "qt")
try:
    loaded = plugins.get_external_plugin("flipstarter", force_load=True)
    assert loaded is not None
    assert type(loaded).__module__ == "electroncash_external_plugins.flipstarter.qt"
    assert loaded.shortName() == "Flipstarter"
finally:
    plugins.stop()
print("PASS verified Flipstarter artifact through Electron Cash plugin discovery")
'''
    result = run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            PYTHON,
            IMAGE,
            "-c",
            code,
        ],
        timeout=60,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "PASS verified Flipstarter artifact through Electron Cash plugin discovery" in result.stdout


def main() -> None:
    test_flipstarter_manifest_identity()
    test_verified_flipstarter_artifact_is_discoverable()
    print("PASS Flipstarter plugin checks")


if __name__ == "__main__":
    main()
