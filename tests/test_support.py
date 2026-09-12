"""Shared candidate-image and disposable-resource helpers for acceptance tests."""

from __future__ import annotations

import os
import re
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
ENV_DEFAULTS = {
    key: value
    for key, value in (
        line.split("=", 1)
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    )
}


def _image(variable: str, default: str, prefix: str) -> str:
    value = os.environ.get(variable, default)
    if not re.fullmatch(r"[a-z0-9./_-]+:[A-Za-z0-9_.-]+", value):
        raise AssertionError(f"invalid {variable} image reference")
    if os.environ.get("CI_CANDIDATE_IMAGES") == "1" and not value.startswith(prefix):
        raise AssertionError(f"{variable} must select a unique CI candidate image")
    return value


def electron_cash_image() -> str:
    return _image(
        "ELECTRON_CASH_IMAGE",
        f"electron-cash:{ENV_DEFAULTS['EC_VERSION']}",
        "electron-cash-ci:",
    )


def tor_image() -> str:
    return _image(
        "TOR_IMAGE",
        f"bchforge/electron-cash-docker-tor:{ENV_DEFAULTS['TOR_VERSION']}",
        "bchforge/electron-cash-docker-tor-ci:",
    )


def register_resource(kind: str, name: str) -> str:
    registry = os.environ.get("CI_RESOURCE_REGISTRY")
    if registry:
        with open(registry, "a", encoding="utf-8") as handle:
            handle.write(f"{kind}\t{name}\n")
    return name


def unique_project(prefix: str) -> str:
    base = os.environ.get("CI_PROJECT_PREFIX", "bchforge-test")
    return register_resource("project", f"{base}-{prefix}-{uuid.uuid4().hex}")


def unique_resource(prefix: str, *, kind: str = "volume") -> str:
    base = os.environ.get("CI_PROJECT_PREFIX", "bchforge-test")
    return register_resource(kind, f"{base}-{prefix}-{uuid.uuid4().hex}")
