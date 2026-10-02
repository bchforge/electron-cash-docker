#!/usr/bin/env python3

import os
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from urllib.request import Request, urlopen

from test_support import (docker_ownership as ownership, electron_cash_image, record_cleanup_result,
                          remove_owned_volume, resource_owner, unique_project, unique_resource)


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env.example"
ENV_DEFAULTS = {}
for env_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
    if "=" in env_line and not env_line.startswith("#"):
        key, value = env_line.split("=", 1)
        ENV_DEFAULTS[key] = value
IMAGE = electron_cash_image()
PASSWORD = "cashfusion-test-password"
GATEWAY_PASSWORD = "synthetic-auth-secret"


def run(command, *, env=None, timeout=120):
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=timeout,
    )


def unique_name(prefix):
    return unique_resource(prefix)


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def create_volume(name):
    result = run(["docker", "volume", "create", "--label", "com.bchforge.test=true",
                  "--label", f"{ownership.OWNER_LABEL}={resource_owner()}", name])
    assert result.returncode == 0, result.stdout + result.stderr


def remove_volume(name):
    remove_owned_volume(name)


def remove_gateway_volumes(project):
    for suffix in ("caddy-data", "caddy-config", "caddy-log", "fail2ban-state", "caddy-ban-state", "caddy-control"):
        remove_volume(f"{project}_{suffix}")


def volume_shell(volume, command, *, extra_mounts=()):
    args = [
        "docker",
        "run",
        "--rm",
        "--user",
        "0:0",
        "--mount",
        f"type=volume,src={volume},dst=/data",
    ]
    for source, target in extra_mounts:
        args.extend(["--mount", f"type=volume,src={source},dst={target}"])
    args.extend(["--entrypoint", "/bin/bash", IMAGE, "-c", command])
    result = run(args)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def bootstrap_failure(volume):
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "USE_TOR=false",
            "-e",
            "CASHFUSION_ENABLED=false",
            "--mount",
            f"type=volume,src={volume},dst=/home/electroncash/.electron-cash",
            IMAGE,
        ]
    )
    assert result.returncode != 0
    return result.stdout + result.stderr


def compose_args(project, override, *, chipnet=False):
    args = [
        "docker",
        "compose",
        "--env-file",
        str(ENV_FILE),
        "-p",
        project,
        "-f",
        "docker-compose.yml",
    ]
    args.extend(["-f", str(override)])
    return args


def compose_env(port, *, chipnet=False):
    env = os.environ.copy()
    env.update(
        {
            "CADDY_SITE_ADDRESS": "http://localhost",
            "CADDY_TLS_MODE": "auto",
            "CADDY_EDGE_BIND": "127.0.0.1",
            "CADDY_HTTP_HOST_PORT": str(port),
            "CADDY_HTTPS_HOST_PORT": str(free_port()),
            "BASIC_AUTH_PASSWORD": GATEWAY_PASSWORD,
            "USE_TOR": "false",
            "CHIPNET": "false",
            "TESTNET4": "false",
            "NETWORK": "chipnet" if chipnet else "mainnet",
            "CASHFUSION_ENABLED": "true",
            "WALLET_AUTO_CREATE": "false",
            "TEST_WALLET_PASSWORD": "",
        }
    )
    if chipnet:
        env.update(
            {
                "WALLET_AUTO_CREATE": "true",
                "TEST_WALLET_PASSWORD": PASSWORD,
            }
        )
    return env


def write_volume_override(directory, volume, tor_volume):
    override = Path(directory) / "volume-override.yml"
    override.write_text(
        "services:\n"
        "  electron-cash:\n"
        "    volumes:\n"
        "      - electron-cash-data:/home/electroncash/.electron-cash\n"
        "volumes:\n"
        "  electron-cash-data:\n"
        f"    name: {volume}\n"
        "  tor-data:\n"
        f"    name: {tor_volume}\n",
        encoding="utf-8",
    )
    return override


def compose_run(args, action, *, env, timeout=120):
    result = run([*args, *action], env=env, timeout=timeout)
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout + result.stderr


def container_id(args, *, env):
    result = run([*args, "ps", "-q", "electron-cash"], env=env)
    assert result.returncode == 0, result.stdout + result.stderr
    value = result.stdout.strip()
    assert value, result.stdout + result.stderr
    return value


def wait_for_running(args, *, env):
    deadline = time.time() + 90
    while time.time() < deadline:
        result = run([*args, "ps", "-q", "electron-cash"], env=env)
        if result.returncode == 0 and result.stdout.strip():
            cid = result.stdout.strip()
            state = run(["docker", "inspect", "--format", "{{.State.Status}}", cid])
            if state.stdout.strip() == "running":
                return cid
            if state.stdout.strip() in {"exited", "dead"}:
                logs = run(["docker", "logs", cid])
                raise AssertionError(logs.stdout + logs.stderr)
        time.sleep(1)
    raise AssertionError("electron-cash did not become ready")


def assert_novnc(port):
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            request = Request(
                f"http://127.0.0.1:{port}/",
            )
            with urlopen(request, timeout=2) as response:
                assert response.status == 200
                return
        except Exception:
            time.sleep(1)
    raise AssertionError("noVNC did not become reachable")


def write_sentinel(volume, relative_path, value):
    parent = str(Path(relative_path).parent)
    command = (
        f"mkdir -p /data/{parent} && "
        f"printf '%s' '{value}' > /data/{relative_path}"
    )
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "10001:10001",
            "--mount",
            f"type=volume,src={volume},dst=/data",
            "--entrypoint",
            "/bin/bash",
            IMAGE,
            "-c",
            command,
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr


def assert_sentinel(volume, relative_path, value):
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "10001:10001",
            "--mount",
            f"type=volume,src={volume},dst=/data,readonly",
            "--entrypoint",
            "/bin/bash",
            IMAGE,
            "-c",
            f"test \"$(cat /data/{relative_path})\" = '{value}'",
        ]
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_compose_managed_persistence():
    project = unique_project("compose")
    volume = unique_resource("volume")
    tor_volume = unique_resource("tor-state")
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="bchforge-compose-") as temp_dir:
        override = write_volume_override(temp_dir, volume, tor_volume)
        env = compose_env(port)
        args = compose_args(project, override)
        try:
            compose_run(args, ["up", "-d", "--no-build"], env=env, timeout=180)
            cid = wait_for_running(args, env=env)
            assert_novnc(port)

            top = run(["docker", "top", cid, "-eo", "user,pid,ppid,args"])
            assert top.returncode == 0, top.stdout + top.stderr
            assert "root" not in top.stdout.lower()
            assert (
                run(["docker", "exec", "--user", "10001:10001", cid, "id", "-u"])
                .stdout.strip()
                == "10001"
            )
            assert (
                run(["docker", "exec", "--user", "10001:10001", cid, "id", "-g"])
                .stdout.strip()
                == "10001"
            )
            assert (
                run(["docker", "exec", "--user", "10001:10001", cid, "id", "-G"])
                .stdout.strip()
                == "10001"
            )

            write_sentinel(volume, ".v011-persistence", "mainnet")
            assert_sentinel(volume, ".v011-persistence", "mainnet")
            compose_run(args, ["restart", "electron-cash"], env=env)
            wait_for_running(args, env=env)
            assert_sentinel(volume, ".v011-persistence", "mainnet")

            compose_run(args, ["up", "-d", "--force-recreate", "--no-build"], env=env)
            wait_for_running(args, env=env)
            assert_sentinel(volume, ".v011-persistence", "mainnet")
        finally:
            command = [*args, "down", "--remove-orphans"]
            record_cleanup_result(run(command, env=env, timeout=120), command)
            remove_volume(volume)
            remove_volume(tor_volume)
            remove_gateway_volumes(project)


def test_chipnet_uses_internal_subdirectory():
    project = unique_project("chipnet")
    volume = unique_resource("chipnet-volume")
    tor_volume = unique_resource("chipnet-tor-state")
    port = free_port()
    with tempfile.TemporaryDirectory(prefix="bchforge-chipnet-") as temp_dir:
        override = write_volume_override(temp_dir, volume, tor_volume)
        main_env = compose_env(port)
        main_args = compose_args(project, override)
        chipnet_env = compose_env(port, chipnet=True)
        chipnet_args = compose_args(project, override, chipnet=True)
        try:
            compose_run(main_args, ["up", "-d", "--no-build"], env=main_env, timeout=180)
            wait_for_running(main_args, env=main_env)
            write_sentinel(volume, ".v011-mainnet", "mainnet")
            write_sentinel(volume, "testnet4/.legacy-data", "testnet4")
            compose_run(main_args, ["down", "--remove-orphans"], env=main_env)

            compose_run(chipnet_args, ["up", "-d", "--no-build"], env=chipnet_env, timeout=180)
            cid = wait_for_running(chipnet_args, env=chipnet_env)
            logs = run(["docker", "logs", cid])
            assert "Network: chipnet" in logs.stdout + logs.stderr
            top = run(["docker", "top", cid, "-eo", "user,pid,ppid,args"])
            assert "--chipnet" in top.stdout
            assert_sentinel(volume, ".v011-mainnet", "mainnet")
            assert_sentinel(volume, "testnet4/.legacy-data", "testnet4")
            write_sentinel(volume, "chipnet/.v04-chipnet", "chipnet")
            assert_sentinel(volume, "chipnet/.v04-chipnet", "chipnet")
            compose_run(chipnet_args, ["restart", "electron-cash"], env=chipnet_env)
            wait_for_running(chipnet_args, env=chipnet_env)
            assert_sentinel(volume, "chipnet/.v04-chipnet", "chipnet")
            assert_sentinel(volume, ".v011-mainnet", "mainnet")
        finally:
            command = [*chipnet_args, "down", "--remove-orphans"]
            record_cleanup_result(run(command, env=chipnet_env, timeout=120), command)
            remove_volume(volume)
            remove_volume(tor_volume)
            remove_gateway_volumes(project)


def test_legacy_testnet4_selector_rejected_before_volume_mutation():
    volume = unique_resource("obsolete-testnet4-selector")
    create_volume(volume)
    try:
        result = run(
            [
                "docker", "run", "--pull=never", "--rm", "--network", "none",
                "-e", "USE_TOR=false", "-e", "CASHFUSION_ENABLED=false",
                "-e", "CHIPNET=false", "-e", "TESTNET4=true",
                "--mount", f"type=volume,src={volume},dst=/home/electroncash/.electron-cash", IMAGE,
            ]
        )
        assert result.returncode != 0
        assert "use NETWORK=<network>" in result.stdout + result.stderr
        volume_shell(volume, "test ! -e /data/.electron-cash-docker")
        empty = run([
            "docker", "run", "--pull=never", "--rm", "--network", "none",
            "-e", "USE_TOR=false", "-e", "NETWORK=",
            "--mount", f"type=volume,src={volume},dst=/home/electroncash/.electron-cash", IMAGE,
        ])
        assert empty.returncode != 0
        assert "invalid NETWORK" in empty.stdout + empty.stderr
        volume_shell(volume, "test ! -e /data/.electron-cash-docker")
    finally:
        remove_volume(volume)


def test_unmarked_nonempty_volume_rejected():
    volume = unique_name("unmarked")
    create_volume(volume)
    try:
        volume_shell(volume, "printf '%s' unrelated > /data/unrelated")
        output = bootstrap_failure(volume)
        assert "empty on first use" in output
        assert_sentinel(volume, "unrelated", "unrelated")
    finally:
        remove_volume(volume)


def test_invalid_marker_rejected():
    volume = unique_name("marker")
    create_volume(volume)
    try:
        volume_shell(volume, "printf '%s\\n' invalid > /data/.electron-cash-docker")
        output = bootstrap_failure(volume)
        assert "invalid wallet data marker" in output
    finally:
        remove_volume(volume)


def test_symlink_rejected():
    volume = unique_name("symlink")
    create_volume(volume)
    try:
        volume_shell(
            volume,
            "printf '%s\\n' electron-cash-docker-v0.1 > /data/.electron-cash-docker "
            "&& ln -s /outside /data/link",
        )
        output = bootstrap_failure(volume)
        assert "symbolic links" in output
    finally:
        remove_volume(volume)


def test_incompatible_owner_rejected_without_repair():
    volume = unique_name("ownership")
    create_volume(volume)
    try:
        volume_shell(
            volume,
            "printf '%s\\n' electron-cash-docker-v0.1 > /data/.electron-cash-docker "
            "&& mkdir /data/cache "
            "&& chown 10001:10001 /data /data/.electron-cash-docker "
            "&& chmod 700 /data "
            "&& chmod 600 /data/.electron-cash-docker "
            "&& chmod 755 /data/cache",
        )
        output = bootstrap_failure(volume)
        assert "ownership does not match" in output
        metadata = volume_shell(volume, "stat -c '%u:%g %a' /data/cache")
        assert metadata.strip() == "0:0 755"
    finally:
        remove_volume(volume)


def main():
    test_unmarked_nonempty_volume_rejected()
    test_invalid_marker_rejected()
    test_symlink_rejected()
    test_incompatible_owner_rejected_without_repair()
    test_compose_managed_persistence()
    test_chipnet_uses_internal_subdirectory()
    test_legacy_testnet4_selector_rejected_before_volume_mutation()
    print("PASS persistence, Chipnet subdirectory, legacy selector rejection, and fail-closed volume checks")


if __name__ == "__main__":
    main()
