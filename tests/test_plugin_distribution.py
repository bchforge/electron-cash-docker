#!/usr/bin/env python3
"""Acceptance checks for the trusted plugin distribution boundary."""

from __future__ import annotations

import json
import hashlib
import os
import subprocess
import tempfile
import zipfile
from pathlib import Path

from test_support import electron_cash_image


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_FILE = ROOT / "plugins.json"
BUILDER = ROOT / "docker/plugins/build_plugins.sh"
DOCKERFILE = ROOT / "docker/Dockerfile"
IMAGE = electron_cash_image()


def run(command: list[str], *, env=None, timeout=120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def run_builder(
    manifest: Path, output: Path, *builder_args: str
) -> subprocess.CompletedProcess[str]:
    return run(
        ["bash", str(BUILDER), *builder_args],
        env={
            **os.environ,
            "PLUGIN_MANIFEST": str(manifest),
            "PLUGIN_OUTPUT_DIR": str(output),
        },
    )


def test_manifest_schema_and_verification_wiring() -> None:
    document = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    plugins = document["plugins"]
    assert len(plugins) == 1
    plugin = plugins[0]
    assert set(plugin) == {
        "package_name",
        "source",
        "artifact",
        "version",
        "archive_root",
        "archive_sha256",
        "sha256",
        "enabled",
    }
    assert plugin["source"].startswith("https://")
    assert plugin["artifact"].startswith("https://")
    assert len(plugin["archive_sha256"]) == 64
    assert len(plugin["sha256"]) == 64
    assert plugin["enabled"] is True

    script = BUILDER.read_text(encoding="utf-8")
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")
    assert "archive_sha256" in script
    assert '"sha256"' in script
    assert "--verify-only" in script
    assert "SOURCE HASH MISMATCH" in script
    assert "ZIP HASH MISMATCH" in script
    assert "COPY --from=plugin-builder /build-plugins/zips/ /preinstalled-plugins/" in dockerfile


def test_manifest_rejects_missing_and_malformed_hashes() -> None:
    original = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    for mutation in ("missing", "malformed"):
        document = json.loads(json.dumps(original))
        if mutation == "missing":
            del document["plugins"][0]["sha256"]
        else:
            document["plugins"][0]["sha256"] = "not-a-sha256"

        with tempfile.TemporaryDirectory(prefix="plugin-manifest-") as temporary:
            root = Path(temporary)
            manifest = root / "plugins.json"
            manifest.write_text(json.dumps(document), encoding="utf-8")
            result = run_builder(manifest, root / "zips", "--verify-only")
        assert result.returncode != 0
        assert "missing" in result.stdout + result.stderr or "invalid sha256" in (
            result.stdout + result.stderr
        )


def test_real_builder_builds_and_verifies_artifact() -> None:
    document = json.loads(MANIFEST_FILE.read_text(encoding="utf-8"))
    plugin = document["plugins"][0]
    temporary_path = None
    with tempfile.TemporaryDirectory(prefix="plugin-build-") as temporary:
        temporary_path = Path(temporary)
        output = temporary_path / "zips"
        result = run_builder(MANIFEST_FILE, output)
        assert result.returncode == 0, result.stdout + result.stderr
        assert "All trusted plugins built and verified" in result.stdout

        artifact = output / f'{plugin["package_name"]}-{plugin["version"]}.zip'
        assert artifact.is_file()
        assert hashlib.sha256(artifact.read_bytes()).hexdigest() == plugin["sha256"]
        assert f'ZIP SHA-256: {plugin["sha256"]}' in result.stdout

        with zipfile.ZipFile(artifact) as archive:
            entries = archive.infolist()
            assert entries[0].filename == "manifest.json"
            assert [entry.filename for entry in entries[1:]] == sorted(
                entry.filename for entry in entries[1:]
            )
            assert all(entry.date_time == (1980, 1, 1, 0, 0, 0) for entry in entries)

    assert temporary_path is not None and not temporary_path.exists()


def test_incorrect_zip_hash_fails_closed() -> None:
    document = {
        "plugins": [
            {
                "package_name": "sample",
                "source": "https://example.invalid/sample",
                "artifact": "https://example.invalid/sample.tar.gz",
                "version": "1",
                "archive_root": "sample-1",
                "archive_sha256": "0" * 64,
                "sha256": "0" * 64,
                "enabled": True,
            }
        ]
    }
    with tempfile.TemporaryDirectory(prefix="plugin-hash-") as temporary:
        root = Path(temporary)
        manifest = root / "plugins.json"
        output = root / "zips"
        output.mkdir()
        manifest.write_text(json.dumps(document), encoding="utf-8")
        with zipfile.ZipFile(output / "sample-1.zip", "w") as archive:
            archive.writestr("manifest.json", "{}")
        result = run_builder(manifest, output, "--verify-only")
    assert result.returncode != 0
    assert "ZIP HASH MISMATCH" in result.stdout + result.stderr


def test_runtime_plugin_path_has_no_download_or_latest_fallback() -> None:
    script = BUILDER.read_text(encoding="utf-8")
    entrypoint = (ROOT / "docker/entrypoint.sh").read_text(encoding="utf-8")
    assert "latest" not in script.lower()
    assert "git clone" not in script
    assert "curl" not in entrypoint
    assert "/preinstalled-plugins" in entrypoint


def main() -> None:
    test_manifest_schema_and_verification_wiring()
    test_manifest_rejects_missing_and_malformed_hashes()
    test_real_builder_builds_and_verifies_artifact()
    test_incorrect_zip_hash_fails_closed()
    test_runtime_plugin_path_has_no_download_or_latest_fallback()
    print("PASS trusted plugin distribution checks")


if __name__ == "__main__":
    main()
