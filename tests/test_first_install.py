#!/usr/bin/env python3
"""Cold public Compose install using the documented dotenv and default image names."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from test_support import (
    ROOT,
    docker_ownership,
    default_builder_infrastructure_category,
    register_resource,
    report_infrastructure_blocker,
    remove_owned_volume,
    resource_owner,
    unique_project,
    unique_resource,
)


DOCKER = os.environ.get("CI_REAL_DOCKER") or shutil.which("docker") or "docker"
SERVICES = ("electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban")
IMAGE_VARIABLES = ("ELECTRON_CASH_IMAGE", "TOR_IMAGE", "AUTH_SESSION_IMAGE",
                   "CADDY_IMAGE", "FAIL2BAN_IMAGE")
HOST_OVERRIDES = (
    *IMAGE_VARIABLES, "ECD_HW_IMAGE", "BASIC_AUTH_PASSWORD", "ECD_WALLET_VOLUME", "ECD_TOR_VOLUME",
    "CADDY_HTTP_HOST_PORT", "CADDY_HTTPS_HOST_PORT", "NETWORK", "DISPLAY", "XAUTHORITY",
    "COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PATH_SEPARATOR", "DOCKER_DEFAULT_PLATFORM",
    "BUILDX_BUILDER", "CI_CANDIDATE_IMAGES",
)


def run(command: list[str], *, env: dict[str, str], timeout: int = 600) -> subprocess.CompletedProcess[str]:
    is_docker = bool(command and command[0] == "docker")
    if is_docker:
        command = [DOCKER, *command[1:]]
    try:
        return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        if is_docker:
            output = error.stdout or error.stderr or "Docker command exceeded its timeout"
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            report_infrastructure_blocker("DOCKER_COMMAND_TIMEOUT", output)
        raise


def free_port() -> str:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return str(listener.getsockname()[1])
    finally:
        listener.close()


def write_first_run_env(example: Path, destination: Path, password: str,
                        wallet: str, tor: str) -> None:
    changes = {"BASIC_AUTH_PASSWORD": password,
               "CADDY_HTTP_HOST_PORT": free_port(), "CADDY_HTTPS_HOST_PORT": free_port()}
    lines = []
    seen = set()
    for line in example.read_text(encoding="utf-8").splitlines():
        key, separator, _value = line.partition("=")
        if separator and key in changes:
            lines.append(f"{key}={changes[key]}")
            seen.add(key)
        else:
            lines.append(line)
    if seen != set(changes):
        raise AssertionError(".env.example is missing documented first-run settings")
    lines.extend((f"ECD_WALLET_VOLUME={wallet}", f"ECD_TOR_VOLUME={tor}"))
    descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write("\n".join(lines) + "\n")
    destination.chmod(0o600)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600


def dotenv_keys(path: Path) -> set[str]:
    return {key for line in path.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#") and (key := line.partition("=")[0])}


def wait_healthy(compose: list[str], service: str, env: dict[str, str], timeout: int = 300) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container_result = run([*compose, "ps", "-q", service], env=env, timeout=60)
        container = container_result.stdout.strip()
        if container:
            status = run(["docker", "inspect", "--format", "{{.State.Health.Status}}", container], env=env)
            if status.returncode == 0 and status.stdout.strip() == "healthy":
                return container
            if status.returncode == 0 and status.stdout.strip() == "unhealthy":
                raise AssertionError(f"first-run service {service} became unhealthy")
        time.sleep(1)
    raise AssertionError(f"first-run service {service} did not become healthy")


def assert_marker(container: str, marker: str, env: dict[str, str]) -> None:
    checked = run(["docker", "exec", "--user", "10001:10001", container,
                   "/opt/electroncash-venv/bin/python", "-c",
                   "import pathlib,sys;assert pathlib.Path(sys.argv[1]).read_text()=='retained'", marker], env=env)
    assert checked.returncode == 0, "user wallet-volume data did not survive restart/recreation"


def record_generated_outputs(images: dict[str, str], env: dict[str, str], owner: str,
                             registry: str | None) -> None:
    if not registry:
        return
    for reference in images.values():
        inspected = run(["docker", "image", "inspect", "--format", "{{.Id}}", reference], env=env)
        if inspected.returncode == 0:
            image_id = inspected.stdout.strip()
        elif "no such image" in inspected.stderr.lower() or "no such object" in inspected.stderr.lower():
            image_id = None
        else:
            raise AssertionError("unable to establish the product image result after first-run build")
        docker_ownership.record_image_attempt(Path(registry), reference, owner, image_id, retain=False)


def main() -> None:
    example = ROOT / ".env.example"
    example_hash = hashlib.sha256(example.read_bytes()).hexdigest()
    project = unique_project("public-first-install")
    wallet = unique_resource("public-first-install-wallet")
    tor = unique_resource("public-first-install-tor")
    owner = resource_owner()
    environment = os.environ.copy()
    for name in {*HOST_OVERRIDES, *dotenv_keys(example)}:
        environment.pop(name, None)
    for name in tuple(environment):
        if name.startswith("COMPOSE_"):
            environment.pop(name, None)
    environment["CI_RESOURCE_OWNER"] = owner

    with tempfile.TemporaryDirectory(prefix="ecd-first-install-") as temporary:
        env_file = Path(temporary) / ".env"
        password = uuid.uuid4().hex
        write_first_run_env(example, env_file, password, wallet, tor)
        compose = ["docker", "compose", "--project-directory", str(ROOT), "--env-file", str(env_file),
                   "-p", project, "-f", str(ROOT / "docker-compose.yml")]
        resolved = run([*compose, "config", "--format", "json"], env=environment)
        assert resolved.returncode == 0, "the securely configured first-run .env did not resolve"
        model = json.loads(resolved.stdout)
        services = model["services"]
        assert set(services) == set(SERVICES)
        assert services["electron-cash"]["environment"]["NETWORK"] == "mainnet"
        assert services["electron-cash"]["environment"]["MODE"] == "novnc"
        assert services["electron-cash"]["environment"]["USE_TOR"] == "true"
        assert services["electron-cash"]["environment"]["CASHFUSION_ENABLED"] == "true"
        assert services["electron-cash"]["environment"]["JSONRPC_ENABLED"] == "false"
        assert all(service.get("build") and service.get("pull_policy") == "never"
                   for service in services.values())
        image_refs = {name: config["image"] for name, config in services.items()}
        expected_images = {
            "electron-cash": f"electron-cash:{services['electron-cash']['build']['args']['EC_VERSION']}",
            "tor-proxy": f"bchforge/electron-cash-docker-tor:{services['tor-proxy']['build']['args']['TOR_VERSION']}",
            "auth-session": "electron-cash-docker-auth-session:0.3",
            "caddy": "electron-cash-docker-caddy:0.3",
            "fail2ban": "electron-cash-docker-fail2ban:0.3",
        }
        assert image_refs == expected_images, "first install did not resolve the documented local product image tags"
        assert "BUILDX_BUILDER" not in environment and "CI_CANDIDATE_IMAGES" not in environment
        for image in image_refs.values():
            existing = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], env=environment)
            if existing.returncode == 0:
                report_infrastructure_blocker(
                    "CACHED_DEFAULT_PRODUCT_IMAGE",
                    f"cold public install cannot be proved while the unowned default image exists: {image}; "
                    "it was left untouched",
                )
            if "no such image" not in existing.stderr.lower():
                report_infrastructure_blocker("DOCKER_IMAGE_PREFLIGHT", existing.stderr or existing.stdout)
            register_resource("image", image)

        context = run(["docker", "context", "show"], env=environment)
        builder = run(["docker", "buildx", "inspect"], env=environment)
        engine = run(["docker", "version", "--format", "{{.Server.Version}}"], env=environment)
        compose_version = run(["docker", "compose", "version", "--short"], env=environment)
        root = run(["docker", "info", "--format", "{{.DockerRootDir}}"], env=environment)
        for label, result in (("context", context), ("default Buildx builder", builder),
                              ("Docker Engine", engine), ("Docker Compose", compose_version),
                              ("Docker storage", root)):
            if result.returncode != 0:
                report_infrastructure_blocker("DEFAULT_BUILDER_PREFLIGHT",
                                               f"unable to inspect {label}: {result.stderr or result.stdout}")
        selected_builder = next((line.split(":", 1)[1].strip() for line in builder.stdout.splitlines()
                                 if line.strip().startswith("Name:")), "unknown")
        driver = next((line.split(":", 1)[1].strip() for line in builder.stdout.splitlines()
                       if line.strip().startswith("Driver:")), "unknown")
        if selected_builder == "unknown" or driver == "unknown" or not root.stdout.strip():
            report_infrastructure_blocker("DEFAULT_BUILDER_PREFLIGHT",
                                          "Docker returned incomplete selected-builder/storage metadata")
        free_before = shutil.disk_usage(root.stdout.strip()).free
        print(f"FIRST_INSTALL_CONTEXT={context.stdout.strip()} BUILDX_BUILDER={selected_builder} "
              f"DRIVER={driver} ENGINE={engine.stdout.strip()} COMPOSE={compose_version.stdout.strip()} "
              f"FREE_BYTES_BEFORE={free_before} PROJECT={project}", flush=True)

        build_started = False
        browser_password = password
        try:
            # Run the two documented public install commands against genuinely
            # absent default image tags, with only isolated project/volume names
            # and loopback ports added for this acceptance run.
            build_started = True
            built = run([*compose, "build"], env=environment, timeout=1800)
            if built.returncode != 0:
                output = (built.stdout + built.stderr).replace(password, "[REDACTED]")[-8000:]
                infrastructure = default_builder_infrastructure_category(output)
                if infrastructure:
                    report_infrastructure_blocker(infrastructure,
                                                  "plain product Compose first build: " + output)
                print("FIRST_INSTALL_STATUS=FAIL_PRODUCT_FIRST_BUILD", flush=True)
                raise AssertionError("plain product Compose first build failed: " + output)
            build_output = built.stdout + built.stderr
            assert "pull access denied" not in build_output.lower()
            assert hashlib.sha256(example.read_bytes()).hexdigest() == example_hash

            started = run([*compose, "up", "-d"], env=environment, timeout=600)
            if started.returncode != 0:
                output = (started.stdout + started.stderr).replace(password, "[REDACTED]")[-8000:]
                infrastructure = default_builder_infrastructure_category(output)
                if infrastructure:
                    report_infrastructure_blocker(infrastructure,
                                                  "plain product Compose first start: " + output)
                print("FIRST_INSTALL_STATUS=FAIL_PRODUCT_FIRST_START", flush=True)
                raise AssertionError("plain product Compose first start failed: " + output)
            start_output = started.stdout + started.stderr
            assert "pull access denied" not in start_output.lower()
            assert "Building" not in start_output and "Pulling " not in start_output
            assert hashlib.sha256(example.read_bytes()).hexdigest() == example_hash

            containers = {service: wait_healthy(compose, service, environment) for service in SERVICES}
            image_ids = {}
            for service, reference in image_refs.items():
                inspected = run(["docker", "image", "inspect", "--format", "{{.Id}}", reference], env=environment)
                assert inspected.returncode == 0 and inspected.stdout.strip()
                image_ids[service] = inspected.stdout.strip()
            http_port = next(port["published"] for port in services["caddy"]["ports"]
                             if port["target"] == 80)
            browser_url = f"http://localhost:{http_port}"
            browser_env = {**environment, "CI_BROWSER_URL": browser_url,
                           "BROWSER_AUTH_PASSWORD": browser_password}
            browser = run([sys.executable, str(ROOT / "tests/test_auth_browser.py")],
                          env=browser_env, timeout=600)
            if browser.returncode != 0:
                details = (browser.stdout + browser.stderr).replace(password, "[REDACTED]")[-6000:]
                raise AssertionError("real noVNC login/WebSocket acceptance failed: " + details)
            assert password not in browser.stdout + browser.stderr

            marker = "/home/electroncash/.electron-cash/.public-first-install-lifecycle"
            writer = run(["docker", "exec", "--user", "10001:10001", containers["electron-cash"],
                          "/opt/electroncash-venv/bin/python", "-c",
                          "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('retained')", marker],
                         env=environment)
            assert writer.returncode == 0
            stopped = run([*compose, "stop"], env=environment)
            assert stopped.returncode == 0
            started_again = run([*compose, "start"], env=environment)
            assert started_again.returncode == 0
            for service in SERVICES:
                wait_healthy(compose, service, environment)
            app = wait_healthy(compose, "electron-cash", environment)
            assert_marker(app, marker, environment)

            recreated = run([*compose, "up", "-d", "--force-recreate"], env=environment, timeout=240)
            assert recreated.returncode == 0
            assert "Building" not in recreated.stdout and "Pulling " not in recreated.stdout
            for service, reference in image_refs.items():
                inspected = run(["docker", "image", "inspect", "--format", "{{.Id}}", reference], env=environment)
                assert inspected.returncode == 0 and inspected.stdout.strip() == image_ids[service]
            app = wait_healthy(compose, "electron-cash", environment)
            assert_marker(app, marker, environment)
            browser = run([sys.executable, str(ROOT / "tests/test_auth_browser.py")],
                          env=browser_env, timeout=600)
            assert browser.returncode == 0 and password not in browser.stdout + browser.stderr
            print("PASS public Compose cold browser install, login/RFB, warm start, stop/start, "
                  "recreate and persistent mainnet state", flush=True)
        finally:
            if build_started:
                record_generated_outputs(image_refs, environment, owner,
                                         environment.get("CI_RESOURCE_REGISTRY"))
            down = run([*compose, "down", "--remove-orphans"], env=environment, timeout=240)
            assert down.returncode == 0, "task-owned first-install Compose cleanup failed"
            for volume in (wallet, tor, *(project + suffix for suffix in (
                    "_caddy-data", "_caddy-config", "_caddy-log", "_fail2ban-state",
                    "_caddy-ban-state", "_caddy-control"))):
                remove_owned_volume(volume)
            after_containers = run(["docker", "ps", "-aq", "--filter",
                                    f"label=com.docker.compose.project={project}"], env=environment)
            after_networks = run(["docker", "network", "ls", "-q", "--filter",
                                  f"label=com.docker.compose.project={project}"], env=environment)
            assert (after_containers.returncode == 0 and not after_containers.stdout.strip() and
                    after_networks.returncode == 0 and not after_networks.stdout.strip())
            print(f"FIRST_INSTALL_FREE_BYTES_AFTER={shutil.disk_usage(root.stdout.strip()).free} "
                  f"PRODUCT_IMAGES_BUILT={sum(1 for reference in image_refs.values() if
                      run(['docker','image','inspect',reference],env=environment).returncode==0)}", flush=True)
        assert hashlib.sha256(example.read_bytes()).hexdigest() == example_hash


if __name__ == "__main__":
    main()
