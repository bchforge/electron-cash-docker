#!/usr/bin/env python3
"""Prove that the configured image contains the requested Electron Cash build."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from test_support import electron_cash_image


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
EXPECTED_VERSION = "4.4.6"
EXPECTED_COMMIT = "9d500949b38dd181a986382eb0c2f6061b829fec"
EXPECTED_ARCHIVE_SHA256 = (
    "fc21dbae10055dee5e4f11a936691576059b40b85107b701221a54c744abd7b7"
)
PYTHON = "/opt/electroncash-venv/bin/python"


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    # The checked-in env file, not a caller's shell override, is under test.
    for key in ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256"):
        environment.pop(key, None)
    return subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        text=True,
        capture_output=True,
        check=False,
    )


def parse_env() -> dict[str, str]:
    values = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            values[key] = value
    return values


def test_declared_pins() -> dict[str, str]:
    values = parse_env()
    assert values["EC_VERSION"] == EXPECTED_VERSION
    assert values["EC_COMMIT"] == EXPECTED_COMMIT
    assert values["EC_ARCHIVE_SHA256"] == EXPECTED_ARCHIVE_SHA256
    return values


def test_compose_image(values: dict[str, str]) -> str:
    result = run(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "config",
            "--format",
            "json",
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    resolved = json.loads(result.stdout)
    image = resolved["services"]["electron-cash"]["image"]
    assert image == electron_cash_image()
    assert values["EC_VERSION"] == EXPECTED_VERSION
    return image


def test_runtime_package(image: str) -> None:
    inspected = run(["docker", "image", "inspect", image])
    assert inspected.returncode == 0, (
        f"{image} must be built locally before running this regression test\n"
        + inspected.stdout
        + inspected.stderr
    )
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
            image,
            "-c",
            (
                "from electroncash.version import PACKAGE_VERSION; "
                "from importlib.metadata import version; "
                "package = version('Electron-Cash'); "
                "print(PACKAGE_VERSION); print(package); "
                "assert PACKAGE_VERSION == '4.4.6'; "
                "assert package == '4.4.6'"
            ),
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.splitlines() == [EXPECTED_VERSION, EXPECTED_VERSION]


def main() -> None:
    values = test_declared_pins()
    image = test_compose_image(values)
    test_runtime_package(image)
    print("PASS Electron Cash pins, Compose image tag, and installed package version")


if __name__ == "__main__":
    main()
