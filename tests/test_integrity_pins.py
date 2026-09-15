#!/usr/bin/env python3
"""Semantic checks for critical upstream identity and integrity tuples."""

from __future__ import annotations

import re
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"


def parse_env() -> dict[str, str]:
    return {
        key: value
        for key, value in (
            line.split("=", 1)
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        )
    }


def tag_commit(repository: str, tag: str) -> str:
    result = subprocess.run(
        ["git", "ls-remote", "--tags", repository, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"],
        text=True,
        capture_output=True,
        check=False,
        timeout=60,
    )
    if result.returncode != 0:
        raise AssertionError(result.stderr)
    refs = {
        ref: commit
        for line in result.stdout.splitlines()
        if "\t" in line
        for commit, ref in [line.split("\t", 1)]
    }
    commit = refs.get(f"refs/tags/{tag}^{{}}") or refs.get(f"refs/tags/{tag}")
    if not commit:
        raise AssertionError(f"upstream tag not found: {repository} {tag}")
    return commit


def validate_tuple(version: str, commit: str, resolver) -> None:
    expected = resolver(version)
    if commit != expected:
        raise AssertionError(f"commit {commit} does not identify release {version}")


def test_positive_upstream_identity() -> None:
    values = parse_env()
    validate_tuple(
        values["EC_VERSION"],
        values["EC_COMMIT"],
        lambda version: tag_commit("https://github.com/Electron-Cash/Electron-Cash.git", version),
    )
    validate_tuple(
        f"v{values['NOVNC_VERSION']}",
        values["NOVNC_COMMIT"],
        lambda tag: tag_commit("https://github.com/novnc/noVNC.git", tag),
    )

    plugin_text = (ROOT / "plugins.json").read_text(encoding="utf-8")
    assert '"version": "1.5"' in plugin_text
    assert "/archive/v1.5.0/" in plugin_text
    assert "flipstarter-electron-cash-v1.5.0" in plugin_text


def test_mismatched_identity_fails() -> None:
    expected = {"4.4.6": "ec-release", "4.4.5": "old-release"}
    try:
        validate_tuple("4.4.6", "old-release", expected.__getitem__)
    except AssertionError:
        pass
    else:
        raise AssertionError("version-only/commit-only mismatch was accepted")


def test_integrity_metadata_contracts() -> None:
    values = parse_env()
    for key in ("EC_ARCHIVE_SHA256", "NOVNC_ARCHIVE_SHA256", "TOR_SOURCE_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", values[key])
    tor_dockerfile = (ROOT / "docker/tor/Dockerfile").read_text(encoding="utf-8")
    assert "gpgv" in tor_dockerfile
    assert "VALIDSIG" in tor_dockerfile
    assert "does not match the Tor Project checksum file" in tor_dockerfile
    plugin = (ROOT / "plugins.json").read_text(encoding="utf-8")
    assert re.search(r'"archive_sha256": "[0-9a-f]{64}"', plugin)
    assert re.search(r'"sha256": "[0-9a-f]{64}"', plugin)


def main() -> None:
    test_positive_upstream_identity()
    test_mismatched_identity_fails()
    test_integrity_metadata_contracts()
    print("PASS semantic upstream identity and integrity metadata checks")


if __name__ == "__main__":
    main()
