#!/usr/bin/env python3
"""Keep the runtime dependency authority in the consumed manifest."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

EXPECTED = {
    "pyaes": "1.6.1",
    "ecdsa": "0.19.1",
    "requests": "2.32.3",
    "qrcode": "7.4.2",
    "protobuf": "5.29.6",
    "jsonrpclib-pelix": "0.4.0",
    "PySocks": "1.7.1",
    "python-dateutil": "2.9.0",
    "stem": "1.8.2",
    "certifi": "2024.7.4",
    "pathvalidate": "3.2.0",
    "qdarkstyle": "3.2.3",
}


def test_manifest_is_exact_runtime_authority() -> None:
    requirements = {}
    for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#"):
            name, version = line.split("==", 1)
            assert name not in requirements
            requirements[name] = version
    assert requirements == EXPECTED

    dockerfile = (ROOT / "docker" / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY requirements.txt /tmp/requirements.txt" in dockerfile
    assert "--requirement /tmp/requirements.txt" in dockerfile
    assert "pyaes==1.6.1" not in dockerfile


def main() -> None:
    test_manifest_is_exact_runtime_authority()
    print("PASS consumed runtime dependency manifest and remediation pin")


if __name__ == "__main__":
    main()
