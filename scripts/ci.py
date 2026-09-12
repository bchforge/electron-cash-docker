#!/usr/bin/env python3
"""Canonical local and GitHub validation for Electron Cash Docker."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid
from pathlib import Path

from compose_guard import UnsafeComposeModel, validate_resolved_model


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
TRIVY_VERSION = "0.74.0"
TRIVY_ARCHIVE_SHA256 = "2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"
TRIVY_ARCHIVE = f"trivy_{TRIVY_VERSION}_Linux-64bit.tar.gz"


class ValidationError(RuntimeError):
    """A validation check failed."""


def sanitize(text: str) -> str:
    patterns = (
        (r"(?i)(JSONRPC_PASSWORD|TEST_WALLET_PASSWORD)([=: ]+)\S+", r"\1\2[REDACTED]"),
        (r"(?i)(password)([=: ]+)\S+", r"\1\2[REDACTED]"),
    )
    for pattern, replacement in patterns:
        text = re.sub(pattern, replacement, text)
    return text[-16000:]


def run(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
        errors="replace",
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def checked(command: list[str], *, env: dict[str, str] | None = None, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    print(f"[ci] {shutil.which(command[0]) or command[0]} {' '.join(command[1:])}")
    result = run(command, env=env, timeout=timeout)
    if result.returncode != 0:
        raise ValidationError(
            f"command failed ({result.returncode}):\n{sanitize(result.stdout + result.stderr)}"
        )
    return result


def assert_safe_docker_endpoint() -> None:
    for key in ("DOCKER_HOST", "DOCKER_TLS_VERIFY", "DOCKER_CERT_PATH"):
        if os.environ.get(key):
            raise ValidationError(f"unsafe Docker environment variable is set: {key}")
    context = os.environ.get("DOCKER_CONTEXT", "default")
    if context != "default":
        raise ValidationError(f"unexpected Docker context: {context}")

    context_result = checked(
        ["docker", "context", "inspect", "default", "--format", "{{json .Endpoints.docker}}"]
    )
    try:
        endpoint = json.loads(context_result.stdout)
    except json.JSONDecodeError as error:
        raise ValidationError("Docker context endpoint was not valid JSON") from error
    host = endpoint.get("Host", "") if isinstance(endpoint, dict) else ""
    if host and not host.startswith("unix://"):
        raise ValidationError(f"Docker endpoint is not local Unix-socket transport: {host}")
    if any(value in host.lower() for value in ("pro0", "production")):
        raise ValidationError("Docker endpoint references production")
    checked(["docker", "version", "--format", "{{.Server.Version}}"])
    checked(["docker", "compose", "version"])

    existing = checked(
        ["docker", "ps", "-a", "--format", "{{.Labels}}"], timeout=60
    ).stdout.lower()
    if "com.docker.compose.project=electron-cash-docker" in existing:
        raise ValidationError("Docker daemon already contains the production Compose project")
    volumes = checked(["docker", "volume", "ls", "--format", "{{.Name}}"], timeout=60).stdout.splitlines()
    if {"bchforge-electron-cash-data", "bchforge-electron-cash-tor-data"}.intersection(volumes):
        raise ValidationError("Docker daemon already contains the production wallet/Tor volumes")


def free_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def candidate_names() -> tuple[str, str, str]:
    suffix = f"{os.environ.get('GITHUB_RUN_ID', 'local')}-{uuid.uuid4().hex[:12]}".lower()
    return (
        f"electron-cash-ci:{suffix}",
        f"bchforge/electron-cash-docker-tor-ci:{suffix}",
        f"bchforge-v021-{suffix}",
    )


def write_compose_override(directory: Path, ec_image: str, tor_image: str, project: str) -> Path:
    override = directory / "ci-isolation.yml"
    override.write_text(
        "services:\n"
        "  electron-cash:\n"
        f"    image: {ec_image}\n"
        "    volumes:\n"
        "      - electron-cash-data:/home/electroncash/.electron-cash\n"
        "  tor-proxy:\n"
        f"    image: {tor_image}\n"
        "    volumes:\n"
        "      - tor-data:/var/lib/tor\n"
        "volumes:\n"
        "  electron-cash-data:\n"
        f"    name: {project}-wallet\n"
        "  tor-data:\n"
        f"    name: {project}-tor\n"
        "networks:\n"
        "  electron-network:\n"
        f"    name: {project}-network\n",
        encoding="utf-8",
    )
    return override


def compose_command(project: str, override: Path) -> list[str]:
    return [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-p",
        project,
        "-f",
        "docker-compose.yml",
        "-f",
        str(override),
    ]


def resolved_model(command: list[str], env: dict[str, str]) -> dict:
    result = checked([*command, "config", "--format", "json"], env=env)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValidationError("resolved Compose model was not valid JSON") from error


def validate_model(model: dict, ec_image: str, tor_image: str, project: str) -> None:
    try:
        validate_resolved_model(
            model,
            expected_ec_image=ec_image,
            expected_tor_image=tor_image,
            expected_wallet_volume=f"{project}-wallet",
            expected_tor_volume=f"{project}-tor",
            expected_network=f"{project}-network",
            expected_project=project,
        )
    except UnsafeComposeModel as error:
        raise ValidationError(f"unsafe resolved Compose model: {error}") from error
    print(f"[ci] isolated Compose model validated for project {project}")


def fast() -> None:
    checked([sys.executable, str(ROOT / "tests" / "test_fast.py")])
    environment = os.environ.copy()
    environment.update({"NOVNC_BIND": "127.0.0.1", "NOVNC_HOST_PORT": str(free_port())})
    checked(
        [
            "docker",
            "compose",
            "--env-file",
            str(ENV_FILE),
            "config",
            "--format",
            "json",
        ],
        env=environment,
    )
    print("PASS fast validation (source checks and Compose resolution only; no image/runtime acceptance)")


def ensure_trivy(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    configured = os.environ.get("TRIVY_BIN")
    if configured:
        path = Path(configured)
        if not path.is_file() or not os.access(path, os.X_OK):
            raise ValidationError(f"TRIVY_BIN is not executable: {configured}")
        return path
    installed = shutil.which("trivy")
    if installed:
        return Path(installed)

    archive_path = directory / TRIVY_ARCHIVE
    url = f"https://github.com/aquasecurity/trivy/releases/download/v{TRIVY_VERSION}/{TRIVY_ARCHIVE}"
    print(f"[ci] downloading pinned Trivy {TRIVY_VERSION}")
    try:
        with urllib.request.urlopen(url, timeout=120) as response, archive_path.open("wb") as output:
            shutil.copyfileobj(response, output)
    except Exception as error:
        raise ValidationError(f"unable to download Trivy {TRIVY_VERSION}: {error}") from error
    import hashlib

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    if digest != TRIVY_ARCHIVE_SHA256:
        raise ValidationError("Trivy archive SHA-256 verification failed")
    with tarfile.open(archive_path, "r:gz") as archive:
        archive.extract("trivy", directory)
    path = directory / "trivy"
    path.chmod(0o755)
    return path


def scan_image(trivy: Path, image: str, report_dir: Path, cache_dir: Path) -> list[dict]:
    report = report_dir / ("electron-cash.json" if image.startswith("electron-cash") else "tor.json")
    version = checked([str(trivy), "version"], timeout=60)
    (report_dir / "trivy-version.txt").write_text(version.stdout, encoding="utf-8")
    result = run(
        [
            str(trivy),
            "image",
            "--cache-dir",
            str(cache_dir),
            "--scanners",
            "vuln",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            "--output",
            str(report),
            "--exit-code",
            "0",
            image,
        ],
        timeout=900,
    )
    if result.returncode != 0:
        raise ValidationError(f"Trivy failed for {image}:\n{sanitize(result.stdout + result.stderr)}")
    if not report.is_file() or report.stat().st_size == 0:
        raise ValidationError(f"Trivy produced no report for {image}")
    try:
        document = json.loads(report.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValidationError(f"Trivy report was invalid for {image}") from error
    vulnerabilities = []
    for result_entry in document.get("Results", []):
        vulnerabilities.extend(result_entry.get("Vulnerabilities") or [])
    fixed = [item for item in vulnerabilities if item.get("FixedVersion")]
    no_fix = [item for item in vulnerabilities if not item.get("FixedVersion")]
    if no_fix:
        print(
            f"[ci] {image}: {len(no_fix)} HIGH/CRITICAL finding(s) have no available fix; "
            "reported for explicit maintainer disposition and not treated as safe"
        )
        for item in no_fix:
            print(f"[ci] no-fix {item.get('VulnerabilityID')} {item.get('PkgName')} {item.get('Severity')}")
    if fixed:
        details = ", ".join(
            f"{item.get('VulnerabilityID')}:{item.get('PkgName')}->{item.get('FixedVersion')}"
            for item in fixed
        )
        raise ValidationError(f"fixable HIGH/CRITICAL vulnerabilities in {image}: {details}")
    return vulnerabilities


def cleanup_registry(registry: Path) -> None:
    if not registry.exists():
        return
    projects = []
    volumes = []
    containers = []
    networks = []
    for line in registry.read_text(encoding="utf-8").splitlines():
        kind, _, name = line.partition("\t")
        if kind == "project":
            projects.append(name)
        elif kind == "volume":
            volumes.append(name)
        elif kind == "container":
            containers.append(name)
        elif kind == "network":
            networks.append(name)
    for project in dict.fromkeys(projects):
        containers = run(
            ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"]
        ).stdout.split()
        if containers:
            run(["docker", "rm", "-f", *containers], timeout=120)
        networks = run(
            ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"]
        ).stdout.split()
        if networks:
            run(["docker", "network", "rm", *networks], timeout=120)
    if volumes:
        run(["docker", "volume", "rm", *dict.fromkeys(volumes)], timeout=120)
    if containers:
        run(["docker", "rm", "-f", *dict.fromkeys(containers)], timeout=120)
    if networks:
        run(["docker", "network", "rm", *dict.fromkeys(networks)], timeout=120)


def acceptance() -> None:
    assert_safe_docker_endpoint()
    ec_image, tor_image, project = candidate_names()
    environment = os.environ.copy()
    environment.update(
        {
            "ELECTRON_CASH_IMAGE": ec_image,
            "TOR_IMAGE": tor_image,
            "CI_CANDIDATE_IMAGES": "1",
            "CI_PROJECT_PREFIX": project,
            "CI_REPORT_DIR": os.environ.get("CI_REPORT_DIR", ""),
            "NOVNC_BIND": "127.0.0.1",
            "NOVNC_HOST_PORT": str(free_port()),
            "USE_TOR": "false",
            "CASHFUSION_ENABLED": "true",
            "CASHFUSION_AUTO_FUSE": "false",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
        }
    )
    with tempfile.TemporaryDirectory(prefix="bchforge-v021-ci-") as temporary:
        temporary_path = Path(temporary)
        registry = temporary_path / "resources.tsv"
        environment["CI_RESOURCE_REGISTRY"] = str(registry)
        report_dir = Path(environment["CI_REPORT_DIR"]) if environment["CI_REPORT_DIR"] else temporary_path / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        cache_dir = temporary_path / "trivy-cache"
        cache_dir.mkdir()
        override = write_compose_override(temporary_path, ec_image, tor_image, project)
        command = compose_command(project, override)
        try:
            model = resolved_model(command, environment)
            validate_model(model, ec_image, tor_image, project)
            checked([*command, "--progress", "plain", "build", "--pull", "--no-cache"], env=environment, timeout=1800)
            ec_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", ec_image]).stdout.strip()
            tor_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", tor_image]).stdout.strip()
            if not ec_id or not tor_id:
                raise ValidationError("candidate image ID was empty")
            print(f"CANDIDATE_ELECTRON_CASH_IMAGE={ec_image} ID={ec_id}")
            print(f"CANDIDATE_TOR_IMAGE={tor_image} ID={tor_id}")

            trivy = ensure_trivy(temporary_path / "trivy")
            (temporary_path / "trivy").mkdir(exist_ok=True)
            scan_image(trivy, ec_image, report_dir, cache_dir)
            scan_image(trivy, tor_image, report_dir, cache_dir)
            checked([sys.executable, str(ROOT / "tests" / "test_integrity_pins.py")], env=environment, timeout=180)
            for test in (
                "test_electron_cash_version.py",
                "test_plugin_distribution.py",
                "test_flipstarter_plugin.py",
                "test_novnc_sharing.py",
                "test_novnc_websocket_heartbeat.py",
                "test_persistence.py",
                "test_cashfusion_states.py",
                "test_headless.py",
                "test_rpc.py",
                "test_tor_proxy.py",
            ):
                checked([sys.executable, str(ROOT / "tests" / test)], env=environment, timeout=1800)
            print("PASS complete acceptance against freshly built wallet and Tor candidate images")
        finally:
            cleanup_registry(registry)
            run(["docker", "image", "rm", ec_image, tor_image], timeout=120)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("fast", "acceptance"))
    args = parser.parse_args()
    try:
        if args.mode == "fast":
            fast()
        else:
            acceptance()
    except (ValidationError, subprocess.TimeoutExpired) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
