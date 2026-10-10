#!/usr/bin/env python3
"""Require runtime banners to use the image's authoritative product version."""

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "docker" / "entrypoint.sh"
COMPOSE = ROOT / "docker-compose.yml"
VERSION = ROOT / "VERSION"


def test_runtime_version_is_configured() -> None:
    entrypoint = ENTRYPOINT.read_text(encoding="utf-8")
    compose = COMPOSE.read_text(encoding="utf-8")

    # The startup contract accepts major.minor; a release bump is not a failure.
    assert re.fullmatch(r"[0-9]+\.[0-9]+", VERSION.read_text(encoding="utf-8").strip())
    assert "ECD_VERSION_FILE=/etc/electroncash-docker/VERSION" in entrypoint
    assert "ECD_PRODUCT_VERSION=$(tr -d" in entrypoint
    assert 'echo "[*] Starting ${ECD_PRODUCT_VERSION} noVNC wallet"' in entrypoint
    assert 'echo "  Electron Cash Docker v${ECD_PRODUCT_VERSION}"' in entrypoint
    assert "ECD_PRODUCT_VERSION" not in compose
    assert "COPY VERSION /etc/electroncash-docker/VERSION" in (ROOT / "docker/Dockerfile").read_text(encoding="utf-8")
    assert "COPY VERSION /etc/electroncash-docker/VERSION" in (ROOT / "docker/auth-session/Dockerfile").read_text(encoding="utf-8")
    assert not re.search(r'Starting v?[0-9]+\.[0-9]+|Electron Cash Docker v[0-9]+\.[0-9]+', entrypoint)


def main() -> None:
    test_runtime_version_is_configured()
    print("PASS runtime product version banner is authoritative")


if __name__ == "__main__":
    main()
