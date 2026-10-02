#!/usr/bin/env python3
"""Exercise the public Compose pull/build policy on the default Buildx builder."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from pathlib import Path

from test_support import default_builder_infrastructure_category, report_infrastructure_blocker


ROOT = Path(__file__).resolve().parents[1]
DOCKER = os.environ.get("CI_REAL_DOCKER") or shutil.which("docker") or "docker"


def run(command: list[str], *, env: dict[str, str], cwd: Path = ROOT,
        timeout: int = 600) -> subprocess.CompletedProcess[str]:
    is_docker = bool(command and command[0] == "docker")
    if is_docker:
        command = [DOCKER, *command[1:]]
    try:
        return subprocess.run(command, cwd=cwd, env=env, text=True, capture_output=True,
                              timeout=timeout, check=False)
    except subprocess.TimeoutExpired as error:
        if is_docker:
            output = error.stdout or error.stderr or "Docker command exceeded its timeout"
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            report_infrastructure_blocker("DOCKER_COMMAND_TIMEOUT", output)
        raise


def default_builder_environment() -> dict[str, str]:
    environment = os.environ.copy()
    # Candidate-image suites may use a task builder. The Compose regression
    # intentionally removes only that selection and uses the current context.
    environment.pop("BUILDX_BUILDER", None)
    return environment


def latest_default_build() -> str | None:
    result = run(["docker", "buildx", "history", "ls", "--builder", "default"],
                 env=default_builder_environment())
    if result.returncode != 0:
        report_infrastructure_blocker("DEFAULT_BUILDER_PREFLIGHT",
                                      "unable to inspect default Buildx history: " +
                                      (result.stderr or result.stdout))
    for line in result.stdout.splitlines():
        fields = line.split()
        if fields and re.fullmatch(r"[a-z0-9]{20,32}", fields[0]):
            return fields[0]
    return None


def assert_project_absent(project: str, env: dict[str, str]) -> None:
    for command in (
        ["docker", "ps", "-aq", "--filter", f"label=com.docker.compose.project={project}"],
        ["docker", "network", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
        ["docker", "volume", "ls", "-q", "--filter", f"label=com.docker.compose.project={project}"],
    ):
        result = run(command, env=env)
        assert result.returncode == 0 and not result.stdout.strip(), "test project name is already in use"


def validate_product_compose() -> None:
    project = "ecd-build-policy-config-" + uuid.uuid4().hex[:10]
    example = ROOT / ".env.example"
    example_hash = hashlib.sha256(example.read_bytes()).hexdigest()
    base = ["docker", "compose", "--env-file", str(example), "-p", project,
            "-f", str(ROOT / "docker-compose.yml")]
    environment = default_builder_environment()
    environment.pop("BASIC_AUTH_PASSWORD", None)
    rejected = run([*base, "config"], env=environment)
    assert rejected.returncode != 0
    assert "BASIC_AUTH_PASSWORD must be set to a real password" in rejected.stderr
    assert not rejected.stdout
    assert hashlib.sha256(example.read_bytes()).hexdigest() == example_hash

    environment["BASIC_AUTH_PASSWORD"] = uuid.uuid4().hex
    environment.update({"DISPLAY": ":87.0", "XAUTHORITY": "/tmp/example authority",
                        "HW_USB_GID": str(os.getgid() or os.getuid() or 10001)})
    resolved = run([*base, "config", "--format", "json"], env=environment)
    assert resolved.returncode == 0, "configured .env.example did not resolve"
    services = json.loads(resolved.stdout)["services"]
    assert set(services) == {"electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"}
    assert all(service.get("build") and service.get("pull_policy") == "never"
               for service in services.values())

    overrides = {**environment,
                 "ELECTRON_CASH_IMAGE": "local-override/electron-cash:checked",
                 "TOR_IMAGE": "local-override/tor:checked",
                 "AUTH_SESSION_IMAGE": "local-override/auth:checked",
                 "CADDY_IMAGE": "local-override/caddy:checked",
                 "FAIL2BAN_IMAGE": "local-override/fail2ban:checked"}
    customized = run([*base, "config", "--format", "json"], env=overrides)
    assert customized.returncode == 0, "local image tag overrides did not resolve"
    custom_services = json.loads(customized.stdout)["services"]
    assert all(service.get("pull_policy") == "never" for service in custom_services.values())
    assert custom_services["electron-cash"]["image"] == overrides["ELECTRON_CASH_IMAGE"]
    assert custom_services["tor-proxy"]["image"] == overrides["TOR_IMAGE"]


def verify_probe_payload(compose: list[str], env: dict[str, str], destination: Path) -> None:
    container_result = run([*compose, "ps", "--all", "-q", "probe"], env=env)
    container = container_result.stdout.strip()
    assert container_result.returncode == 0 and container
    inspected = run(["docker", "inspect", container], env=env)
    assert inspected.returncode == 0, "created probe container is not inspectable"
    container_info = json.loads(inspected.stdout)[0]
    labels = container_info.get("Config", {}).get("Labels", {})
    assert labels.get("com.docker.compose.service") == "probe"
    copied = run(["docker", "cp", f"{container}:/payload", str(destination)], env=env)
    assert copied.returncode == 0, "Compose did not create the expected image container"
    assert destination.read_bytes() == b"compose-built-local-image\n"


def remove_owned_probe_image(image: str, owner: str, recipe: str,
                             env: dict[str, str]) -> None:
    inspected = run(["docker", "image", "inspect", "--format",
                     "{{json .Config.Labels}}|{{.Id}}", image], env=env)
    if inspected.returncode != 0:
        return
    labels_text, separator, image_id = inspected.stdout.strip().partition("|")
    labels = json.loads(labels_text) if separator else {}
    if (labels.get("org.bchforge.compose-policy-owner") != owner or
            labels.get("org.bchforge.compose-policy-recipe") != f"sha256:{recipe}" or not image_id):
        raise AssertionError("refusing to remove a Compose policy image without exact task ownership")
    removed = run(["docker", "image", "rm", "--no-prune", image_id], env=env)
    assert removed.returncode == 0, "unable to remove the exact disposable Compose policy image"


def verify_missing_and_warm_image_behavior() -> str:
    env = default_builder_environment()
    owner = uuid.uuid4().hex
    project = f"ecd-compose-policy-{owner}"
    assert_project_absent(project, env)
    payload = b"compose-built-local-image\n"
    recipe_source = "FROM scratch\nCOPY payload /payload\n"
    recipe = hashlib.sha256(recipe_source.encode() + payload).hexdigest()
    dockerfile = (recipe_source +
                  "ENTRYPOINT [\"/payload\"]\n" +
                  f"LABEL org.bchforge.compose-policy-owner={owner}\n"
                  f"LABEL org.bchforge.compose-policy-recipe=sha256:{recipe}\n")
    image = f"ecd-compose-build-policy:{owner}"
    preflight = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], env=env)
    if preflight.returncode == 0:
        raise AssertionError("task-owned Compose policy image tag already exists")
    if "no such image" not in preflight.stderr.lower():
        report_infrastructure_blocker("DOCKER_IMAGE_PREFLIGHT", preflight.stderr or preflight.stdout)

    with tempfile.TemporaryDirectory(prefix="ecd-compose-policy-context-") as temporary:
        context = Path(temporary)
        (context / "Dockerfile").write_text(dockerfile, encoding="utf-8")
        (context / "payload").write_bytes(payload)
        compose_file = context / "compose.yml"
        compose_file.write_text(
            "services:\n"
            "  probe:\n"
            f"    image: {image}\n"
            "    pull_policy: never\n"
            "    build:\n"
            "      context: .\n"
            "      dockerfile: Dockerfile\n",
            encoding="utf-8",
        )
        compose = ["docker", "compose", "--project-directory", str(context),
                   "-p", project, "-f", str(compose_file)]
        before = latest_default_build()
        try:
            first = run([*compose, "up", "--no-start"], env=env)
            if first.returncode != 0:
                output = first.stderr + first.stdout
                infrastructure = default_builder_infrastructure_category(output)
                if infrastructure:
                    report_infrastructure_blocker(infrastructure,
                                                  "default-builder Compose build: " + output)
                raise AssertionError("Compose could not build/use a missing local image: " + output[-3000:])
            first_output = first.stdout + first.stderr
            assert "pull access denied" not in first_output.lower()
            assert "pulling" not in first_output.lower()
            first_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], env=env)
            assert first_id.returncode == 0 and first_id.stdout.strip()
            image_id = first_id.stdout.strip()
            verify_probe_payload(compose, env, context / "copied-first")
            after_first = latest_default_build()
            assert after_first and after_first != before, "missing image was not built on the default builder"

            stopped = run([*compose, "down"], env=env)
            assert stopped.returncode == 0, "task-owned probe project did not stop cleanly"
            before_warm = latest_default_build()
            warm = run([*compose, "up", "--no-start"], env=env)
            assert warm.returncode == 0, "warm local-image Compose start failed"
            assert "pull access denied" not in (warm.stdout + warm.stderr).lower()
            assert latest_default_build() == before_warm, "warm up unexpectedly started a new image build"
            warm_id = run(["docker", "image", "inspect", "--format", "{{.Id}}", image], env=env)
            assert warm_id.returncode == 0 and warm_id.stdout.strip() == image_id
            verify_probe_payload(compose, env, context / "copied-warm")
        finally:
            cleanup = run([*compose, "down", "--remove-orphans"], env=env)
            assert cleanup.returncode == 0, "task-owned Compose build-policy project cleanup failed"
            assert_project_absent(project, env)
            remove_owned_probe_image(image, owner, recipe, env)

    assert_project_absent(project, env)
    image_check = run(["docker", "image", "inspect", image], env=env)
    assert image_check.returncode != 0, "disposable test image remained after exact cleanup"
    return "cold build and warm reuse"


def main() -> None:
    validate_product_compose()
    result = verify_missing_and_warm_image_behavior()
    print(f"PASS .env.example fail-closed config, product pull policy, default-builder {result}")


if __name__ == "__main__":
    main()
