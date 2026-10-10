#!/usr/bin/env python3
"""Semantic checks for critical upstream identity and integrity tuples."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
EXPECTED_PINS = {
    "EC_VERSION": "4.4.6",
    "EC_COMMIT": "9d500949b38dd181a986382eb0c2f6061b829fec",
    "EC_ARCHIVE_SHA256": "fc21dbae10055dee5e4f11a936691576059b40b85107b701221a54c744abd7b7",
    "NOVNC_VERSION": "1.6.0",
    "NOVNC_COMMIT": "a8dfd6a3ea3c74244f5ebdaa5a7f1023007a7820",
    "NOVNC_ARCHIVE_SHA256": "ebb8eabcd3670ce1a02e4025f03976826c289121cf631183647bd8325b003403",
    "TOR_VERSION": "0.4.9.14",
    "TOR_SOURCE_SHA256": "182449ac1c8ff43278da27b69b02040e11d03d0327db6d9126e4190ec6235e4a",
}


def parse_env() -> dict[str, str]:
    return {
        key: value
        for key, value in (
            line.split("=", 1)
            for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and "=" in line
        )
    }


def validate_tuple(version: str, commit: str, resolver) -> None:
    expected = resolver(version)
    if commit != expected:
        raise AssertionError(f"commit {commit} does not identify release {version}")


def test_positive_upstream_identity() -> None:
    values = parse_env()
    for key, expected in EXPECTED_PINS.items():
        assert values[key] == expected
    assert re.fullmatch(r"[0-9a-f]{40}", values["EC_COMMIT"])
    assert re.fullmatch(r"[0-9a-f]{40}", values["NOVNC_COMMIT"])

    plugin_text = (ROOT / "plugins.json").read_text(encoding="utf-8")
    assert '"version": "1.5"' in plugin_text
    assert "/archive/v1.5.0/" in plugin_text
    assert "flipstarter-electron-cash-v1.5.0" in plugin_text


def test_upstream_identity_matches_recorded_contract() -> None:
    values = parse_env()
    for key, expected in EXPECTED_PINS.items():
        assert values[key] == expected


def test_integrity_metadata_contracts() -> None:
    values = parse_env()
    for key in ("EC_ARCHIVE_SHA256", "NOVNC_ARCHIVE_SHA256", "TOR_SOURCE_SHA256"):
        assert re.fullmatch(r"[0-9a-f]{64}", values[key])
    novnc_dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    assert "git submodule sync -- contrib/secp256k1 && \\" in novnc_dockerfile
    assert "git submodule update --init -- contrib/secp256k1 && \\" in novnc_dockerfile
    assert "git submodule update --init --recursive" not in novnc_dockerfile
    assert "GIT_SUBMODULE_SKIP=1 ./contrib/make_secp" in novnc_dockerfile
    assert "https://codeload.github.com/novnc/noVNC/tar.gz/${NOVNC_COMMIT}" in novnc_dockerfile
    assert "https://github.com/novnc/noVNC/archive/" not in novnc_dockerfile
    tor_dockerfile = (ROOT / "docker/tor/Dockerfile").read_text(encoding="utf-8")
    assert "gpgv" in tor_dockerfile
    assert "VALIDSIG" in tor_dockerfile
    assert "does not match the Tor Project checksum file" in tor_dockerfile
    plugin = (ROOT / "plugins.json").read_text(encoding="utf-8")
    assert re.search(r'"archive_sha256": "[0-9a-f]{64}"', plugin)
    assert re.search(r'"sha256": "[0-9a-f]{64}"', plugin)
    caddy = (ROOT / "docker/caddy/Dockerfile").read_text(encoding="utf-8")
    assert "FROM caddy@sha256:d8542f48d34a9cf4e4c11a478865229840e87e4c96ea3f439101f31a5d35f75f" in caddy
    assert "FROM golang@sha256:cdfd4fe2da6b225d8b40c6b7a105736e548e83ff56d5d8f9394446eeb5eb84e0 AS builder" in caddy
    assert "ARG CADDY_VERSION=2.11.7" in caddy
    assert "ARG CADDY_ARCHIVE_SHA256=86e39de5fa0bc433a9cd574a00e7751059903401f3389c61f8937fd0ad0180f5" in caddy
    assert "go build -mod=readonly" in caddy and "go mod verify" in caddy
    assert "ENV GOTOOLCHAIN=local" in caddy
    assert "libcrypto3=3.5.9-r0" in caddy
    assert "libssl3=3.5.9-r0" in caddy
    fail2ban = (ROOT / "docker/fail2ban/Dockerfile").read_text(encoding="utf-8")
    assert "FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90" in fail2ban


def test_os_package_specs_are_pinned() -> None:
    for path in (ROOT / "docker/Dockerfile", ROOT / "docker/caddy/Dockerfile", ROOT / "docker/tor/Dockerfile", ROOT / "docker/fail2ban/Dockerfile"):
        lines = path.read_text(encoding="utf-8").splitlines()
        collecting = False
        for line in lines:
            original_line = line
            if "apt-get install -y --no-install-recommends" in line or "apk add --no-cache" in line:
                collecting = True
                marker = "apt-get install -y --no-install-recommends" if "apt-get install" in line else "apk add --no-cache"
                line = line.split(marker, 1)[1].split("\\", 1)[0]
            if not collecting:
                continue
            payload = line.split("&&", 1)[0].replace("\\", " ")
            for token in payload.split():
                if token.startswith(("RUN", "apt-get", "install", "apk", "add", "-")):
                    continue
                assert "=" in token, f"unversioned OS package {token!r} in {path}"
            if "&&" in original_line or "\\" not in original_line:
                collecting = False


def test_current_os_pins_and_ledger_source() -> None:
    dockerfile = (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    tor = (ROOT / "docker/tor/Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("curl=8.5.0-2ubuntu10.15") == 3
    assert "xvfb=2:21.1.12-1ubuntu1.8" in dockerfile
    assert "curl=8.5.0-2ubuntu10.15" in tor
    assert "34f5e0c161c08f65dc0d070ba2ff4c315ed21c4b7e0faa32a46862d0dc1b8f55" in dockerfile
    assert "sha256sum -c -" in dockerfile
    assert "btchip-python-0.1.32.tar.gz" in dockerfile


def main() -> None:
    test_positive_upstream_identity()
    test_upstream_identity_matches_recorded_contract()
    test_integrity_metadata_contracts()
    test_os_package_specs_are_pinned()
    test_current_os_pins_and_ledger_source()
    print("PASS semantic upstream identity and integrity metadata checks")


if __name__ == "__main__":
    main()
