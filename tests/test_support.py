"""Shared candidate-image and disposable-resource helpers for acceptance tests."""

from __future__ import annotations

import os
import json
import re
import subprocess
import uuid
from pathlib import Path
import sys
import shutil


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import docker_ownership

_LOCAL_RESOURCE_OWNER = uuid.uuid4().hex
_LOCAL_CLAIMS: list[dict[str, object]] = []
_LOCAL_DOCKER_OWNER_DIRECTORY: Path | None = None
ENV_FILE = ROOT / ".env.example"
ENV_DEFAULTS = {
    key: value
    for key, value in (
        line.split("=", 1)
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#") and "=" in line
    )
}


def default_builder_infrastructure_category(output: str) -> str | None:
    text = output.lower()
    if "lease" in text and any(marker in text for marker in (
            "not found", "no such", "does not exist", "failed to get", "failed to release")):
        return "DEFAULT_BUILDKIT_LEASE"
    if any(marker in text for marker in (
            "cannot connect to the docker daemon", "error during connect", "failed to dial",
            "context deadline exceeded", "no space left on device", "no builder",
            "buildx is not installed", "failed to bootstrap", "failed to start buildkit",
            "driver is not running", "tls handshake timeout")):
        return "DEFAULT_BUILDER"
    return None


def report_infrastructure_blocker(category: str, details: str) -> None:
    print(f"DEFAULT_BUILDER_STATUS=INFRA_FAILURE_{category}", flush=True)
    raise AssertionError(f"default Docker infrastructure blocked acceptance: {details[-4000:]}")


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
    _ensure_standalone_docker_owner()
    owner = os.environ.get("CI_RESOURCE_OWNER", _LOCAL_RESOURCE_OWNER)
    registry = os.environ.get("CI_RESOURCE_REGISTRY")
    if registry:
        claim = docker_ownership.append_claim(Path(registry), kind, name, owner)
    else:
        claim = docker_ownership.reserve_claim(kind, name, owner)
    _LOCAL_CLAIMS.append(claim)
    return name


def resource_owner() -> str:
    return os.environ.get("CI_RESOURCE_OWNER", _LOCAL_RESOURCE_OWNER)


def _ensure_standalone_docker_owner() -> None:
    global _LOCAL_DOCKER_OWNER_DIRECTORY
    if os.environ.get("CI_DOCKER_OWNER_SHIM") == "1":
        return
    if _LOCAL_DOCKER_OWNER_DIRECTORY is not None:
        return
    real_docker = shutil.which("docker")
    if not real_docker:
        raise AssertionError("Docker CLI is required before claiming test resources")
    state_home = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state")).expanduser()
    root = state_home / "electron-cash-docker" / "test-resource-owners"
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if root.is_symlink() or not root.is_dir():
        raise AssertionError("test resource ownership directory is unsafe")
    os.chmod(root, 0o700)
    owner = os.environ.setdefault("CI_RESOURCE_OWNER", _LOCAL_RESOURCE_OWNER)
    directory = root / f"docker-bin-{owner}"
    directory.mkdir(mode=0o700, exist_ok=True)
    registry = root / f"{owner}.jsonl"
    descriptor = os.open(registry, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(descriptor)
    shim = directory / "docker"
    launcher = ("#!/usr/bin/env python3\n"
                f"import sys; sys.path.insert(0, {str(ROOT / 'scripts')!r})\n"
                "from docker_ownership import docker_shim_main\n"
                "raise SystemExit(docker_shim_main())\n")
    shim.write_text(launcher, encoding="utf-8")
    shim.chmod(0o700)
    os.environ["CI_RESOURCE_REGISTRY"] = str(registry)
    os.environ["CI_RESOURCE_EVENT_LOG"] = str(root / f"{owner}.events.jsonl")
    os.environ["CI_REAL_DOCKER"] = real_docker
    os.environ["ECD_REPOSITORY_ROOT"] = str(ROOT)
    os.environ["CI_DOCKER_OWNER_SHIM"] = "1"
    os.environ["PATH"] = str(directory) + os.pathsep + os.environ.get("PATH", "")
    _LOCAL_DOCKER_OWNER_DIRECTORY = directory


def remove_owned_volume(name: str) -> None:
    result = subprocess.run(
        ["docker", "volume", "inspect", name], text=True, capture_output=True, check=False, timeout=60)
    if result.returncode != 0:
        if "no such volume" in result.stderr.lower():
            return
        raise AssertionError(f"cannot verify volume {name} ownership: {result.stderr}")
    labels = json.loads(result.stdout)[0].get("Labels") or {}
    projects = {claim["name"] for claim in _LOCAL_CLAIMS if claim.get("kind") == "project"}
    registry = os.environ.get("CI_RESOURCE_REGISTRY")
    if registry:
        projects.update(claim["name"] for claim in docker_ownership.read_claims(Path(registry))
                        if claim.get("kind") == "project" and claim.get("owner_token") == resource_owner())
    owned = (labels.get(docker_ownership.OWNER_LABEL) == resource_owner() or
             labels.get(docker_ownership.PROJECT_LABEL) in projects or
             labels.get(docker_ownership.ROLLBACK_PROJECT_LABEL) in projects)
    if not owned:
        raise AssertionError(f"refusing to remove unproven Docker volume {name}")
    removed = subprocess.run(
        ["docker", "volume", "rm", name], text=True, capture_output=True, check=False, timeout=60)
    if removed.returncode != 0:
        raise AssertionError(f"unable to remove owned Docker volume {name}: {removed.stderr}")


def remove_owned_container(name: str) -> None:
    inspected = subprocess.run(["docker", "inspect", name], text=True, capture_output=True,
                               check=False, timeout=60)
    if inspected.returncode != 0:
        if "no such object" in inspected.stderr.lower() or "no such container" in inspected.stderr.lower():
            return
        raise AssertionError(f"cannot verify container {name} ownership: {inspected.stderr}")
    containers = json.loads(inspected.stdout)
    if len(containers) != 1:
        raise AssertionError(f"container name did not resolve uniquely: {name}")
    labels = (containers[0].get("Config", {}).get("Labels") or {})
    if labels.get(docker_ownership.OWNER_LABEL) != resource_owner():
        raise AssertionError(f"refusing to remove unproven Docker container {name}")
    removed = subprocess.run(["docker", "rm", "-f", containers[0]["Id"]], text=True,
                             capture_output=True, check=False, timeout=60)
    if removed.returncode != 0:
        raise AssertionError(f"unable to remove owned Docker container {name}: {removed.stderr}")


def record_cleanup_result(result, command: list[str]):
    """Retain cleanup failures so the gate can report them without masking tests."""
    if result.returncode == 0:
        return result
    failure_file = os.environ.get("CI_CLEANUP_FAILURE_FILE")
    if failure_file:
        sanitized = re.sub(
            r"(?i)(password)([=: ]+)\S+",
            r"\1\2[REDACTED]",
            result.stdout + result.stderr,
        )
        with open(failure_file, "a", encoding="utf-8") as handle:
            handle.write(
                json.dumps(
                    {
                        "command": command,
                        "returncode": result.returncode,
                        "output": sanitized[-4000:],
                    },
                    sort_keys=True,
                )
                + "\n"
            )
    return result


def unique_project(prefix: str) -> str:
    base = os.environ.get("CI_PROJECT_PREFIX", "bchforge-test")
    project = register_resource("project", f"{base}-{prefix}-{uuid.uuid4().hex}")
    for suffix in ("-wallet", "-tor", "_caddy-data", "_caddy-config", "_caddy-log",
                    "_fail2ban-state", "_caddy-ban-state", "_caddy-control", "_x11-authority", "_gui-session-state", "_auth-session-data"):
        register_resource("volume", project + suffix)
    return project


def unique_resource(prefix: str, *, kind: str = "volume") -> str:
    base = os.environ.get("CI_PROJECT_PREFIX", "bchforge-test")
    return register_resource(kind, f"{base}-{prefix}-{uuid.uuid4().hex}")
