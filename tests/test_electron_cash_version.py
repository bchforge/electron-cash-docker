#!/usr/bin/env python3
"""Prove that the configured image contains the requested Electron Cash build."""

from __future__ import annotations

import json
import os
import subprocess
import sys
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
sys.path.insert(0, str(ROOT / "docker"))
from network_selection import NETWORK_FLAGS


def run(command: list[str]) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    # The checked-in env file, not a caller's shell override, is under test.
    for key in ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256"):
        environment.pop(key, None)
    environment["BASIC_AUTH_PASSWORD"] = "synthetic-auth-secret"
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


def test_upstream_network_mapping(image: str) -> None:
    """Detect selector and data-path drift in the actual installed pinned image."""
    code = '''import inspect, json, re
from electroncash.commands import get_parser
from electroncash.simple_config import SimpleConfig
parser = get_parser()
flags = {option for action in parser._actions for option in action.option_strings}
source = inspect.getsource(SimpleConfig.electrum_path)
directories = set(re.findall(r"(?:if|elif) self.get\\('([a-z0-9_]+)'\\):\\s+path = os.path.join\\(path, '([a-z0-9_]+)'\\)", source))
print(json.dumps({"flags": sorted(flags), "directories": sorted(directories)}))'''
    result = run(["docker", "run", "--pull=never", "--rm", "--network", "none",
                  "--entrypoint", PYTHON, image, "-c", code])
    assert result.returncode == 0, result.stdout + result.stderr
    upstream = json.loads(result.stdout)
    selected = {flag for flag in NETWORK_FLAGS.values() if flag}
    assert upstream["directories"] == [[key, key] for key in sorted(NETWORK_FLAGS) if key != "mainnet"]
    assert selected <= set(upstream["flags"])


def main() -> None:
    values = test_declared_pins()
    image = test_compose_image(values)
    test_runtime_package(image)
    test_upstream_network_mapping(image)
    print("PASS Electron Cash pins, Compose image tag, and installed package version")


if __name__ == "__main__":
    main()
