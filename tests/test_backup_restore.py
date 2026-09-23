#!/usr/bin/env python3
"""Docker-only archive, validation, and rollback-copy checks."""

from __future__ import annotations

import io
import json
import os
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("ELECTRON_CASH_IMAGE", "electron-cash:4.4.6")
VERSION = os.environ.get("EC_VERSION", "4.4.6")
PASSWORD = "synthetic-backup-secret"
CONFIG_SECRET = "synthetic-config-secret"


def run(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(command, cwd=ROOT, input=input_bytes, capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 120) -> subprocess.CompletedProcess[bytes]:
    result = run(command, input_bytes=input_bytes, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    return result


def resource(prefix: str) -> str:
    return f"ecd-backup-{prefix}-{uuid.uuid4().hex[:12]}"


def create_volume(name: str) -> None:
    checked(["docker", "volume", "create", "--label", "com.bchforge.test=true", name])


def remove_volume(name: str) -> None:
    run(["docker", "volume", "rm", "-f", name])


def base_helper(volume: str, command: list[str], *, volume_readonly: bool = False, archive: Path | None = None, archive_readonly: bool = True, extra_volume: str | None = None, extra_readonly: bool = False) -> list[str]:
    args = [
        "docker", "run", "--pull=never", "--rm", "-i", "--network", "none", "--read-only",
        "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--cap-add=CHOWN", "--cap-add=FOWNER",
        "--security-opt", "no-new-privileges:true", "--user", "0:0",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
        "--mount", f"type=volume,src={volume},dst=/wallet{',readonly' if volume_readonly else ''}",
        "-e", f"BACKUP_NETWORK=mainnet", "-e", f"EC_VERSION={VERSION}",
    ]
    if archive is not None:
        args += ["--mount", f"type=bind,src={archive},dst=/archive,{ 'readonly' if archive_readonly else 'rw' }"]
    if extra_volume is not None:
        suffix = ",readonly" if extra_readonly else ""
        args += ["--mount", f"type=volume,src={extra_volume},dst=/extra{suffix}"]
    args += ["--entrypoint", "/home/electroncash/backup.sh", IMAGE, *command]
    return args


def initialize_volume(name: str, sentinel: str) -> None:
    checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "0:0",
            "--mount", f"type=volume,src={name},dst=/wallet", "--entrypoint", "/bin/bash", IMAGE, "-c",
            "mkdir -p /wallet/wallets && "
            "printf 'electron-cash-docker-v0.1\\n' > /wallet/.electron-cash-docker && "
            "printf '{\"auto_connect\":true,\"rpcpassword\":\"synthetic-config-secret\"}\\n' > /wallet/config && "
            f"printf '{sentinel}\\n' > /wallet/wallets/default_wallet && "
            "chown -R 10001:10001 /wallet && chmod 700 /wallet /wallet/wallets && "
            "chmod 600 /wallet/.electron-cash-docker /wallet/config /wallet/wallets/default_wallet",
        ]
    )


def create_archive(volume: str, path: Path) -> None:
    result = run(
        base_helper(volume, ["create", "--stdout"], volume_readonly=True),
        input_bytes=(PASSWORD + "\n").encode(),
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    path.write_bytes(result.stdout)
    path.chmod(0o600)


def verify_archive(volume: str, path: Path, password: str = PASSWORD) -> subprocess.CompletedProcess[bytes]:
    readable = path.resolve()
    return run(
        base_helper(volume, ["verify", "/archive"], volume_readonly=True, archive=readable),
        input_bytes=(password + "\n").encode(),
    )


def restore_archive(volume: str, path: Path) -> subprocess.CompletedProcess[bytes]:
    return run(
        base_helper(volume, ["restore", "/archive"], archive=path.resolve(), archive_readonly=True),
        input_bytes=(PASSWORD + "\n").encode(),
    )


def replace_archive(volume: str, path: Path) -> subprocess.CompletedProcess[bytes]:
    return run(
        base_helper(volume, ["replace", "/archive"], archive=path.resolve(), archive_readonly=True),
        input_bytes=(PASSWORD + "\n").encode(),
    )


def assert_runtime_tree_is_usable(volume: str) -> None:
    checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--read-only",
            "--mount", f"type=volume,src={volume},dst=/wallet,readonly", "--entrypoint", "/bin/bash", IMAGE,
            "-c", "test -z \"$(find /wallet -xdev -mindepth 0 \\( ! -uid 10001 -o ! -gid 10001 \\) -print -quit)\" && "
                "test \"$(stat -c %a /wallet)\" = 700 && "
                "test \"$(stat -c %a /wallet/wallets)\" = 700 && "
                "test \"$(stat -c %a /wallet/wallets/default_wallet)\" = 600",
        ]
    )
    checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "10001:10001",
            "--mount", f"type=volume,src={volume},dst=/wallet", "--entrypoint", "/bin/bash", IMAGE,
            "-c", "printf 'uid-gid-write\n' > /wallet/wallets/.ownership-probe && "
                "rm /wallet/wallets/.ownership-probe",
        ]
    )


def assert_real_runtime_stays_up(volume: str) -> None:
    container = resource("runtime")
    command = [
        "docker", "run", "--pull=never", "--detach", "--name", container,
        "--label", "com.bchforge.test=true", "--restart", "on-failure:5",
        "--network", "none", "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,size=256m",
        "--tmpfs", "/home/electroncash/.local/share:rw,nosuid,size=64m",
        "--mount", f"type=volume,src={volume},dst=/home/electroncash/.electron-cash",
        "-e", "MODE=novnc", "-e", "USE_TOR=false", "-e", "CASHFUSION_ENABLED=false",
        "-e", "TESTNET4=false", "-e", "WALLET_AUTO_CREATE=false", "-e", "TEST_WALLET_PASSWORD=",
        "-e", "JSONRPC_ENABLED=false", IMAGE,
    ]

    def logs() -> str:
        result = run(["docker", "logs", container])
        return result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace")

    def state() -> tuple[str, int]:
        result = run(["docker", "inspect", "--format", "{{.State.Status}} {{.RestartCount}}", container])
        if result.returncode != 0:
            raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
        status, restart_count = result.stdout.decode().strip().split()
        return status, int(restart_count)

    def port_is_operational() -> bool:
        result = run(
            [
                "docker", "exec", "--user", "10001:10001", container,
                "/opt/electroncash-venv/bin/python", "-c",
                "import socket; s=socket.create_connection(('127.0.0.1', 6080), 1); "
                "s.sendall(b'GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n'); "
                "response=s.recv(128); s.close(); raise SystemExit(0 if b'HTTP/' in response else 1)",
            ],
            timeout=10,
        )
        return result.returncode == 0

    def gui_processes_are_alive() -> tuple[bool, bool]:
        result = run(["docker", "top", container, "-eo", "user,pid,args"])
        if result.returncode != 0:
            return False, False
        process_args = result.stdout.decode(errors="replace")
        return "x11vnc" in process_args, "websockify" in process_args

    started = run(command)
    if started.returncode != 0:
        raise AssertionError(started.stdout.decode(errors="replace") + started.stderr.decode(errors="replace"))

    try:
        deadline = time.monotonic() + 90
        observed = None
        while time.monotonic() < deadline:
            observed = state()
            status, restart_count = observed
            if restart_count:
                raise AssertionError(f"real runtime restarted ({restart_count}):\n{logs()}")
            if status in {"exited", "dead", "restarting"}:
                raise AssertionError(f"real runtime is {status}:\n{logs()}")
            if status == "running":
                x11vnc, websockify = gui_processes_are_alive()
                if port_is_operational() and x11vnc and websockify:
                    break
            time.sleep(1)
        else:
            raise AssertionError(f"real runtime did not become operational (last state {observed}):\n{logs()}")

        for _ in range(5):
            status, restart_count = state()
            assert status == "running", f"real runtime stopped after readiness: {logs()}"
            assert restart_count == 0, f"real runtime entered a restart loop: {logs()}"
            time.sleep(1)

        x11vnc, websockify = gui_processes_are_alive()
        assert x11vnc and websockify
        print(
            f"REAL RUNTIME PASS container={container} volume={volume} "
            "state=running restart_count=0 port=6080/x11vnc/websockify=ready"
        )
    finally:
        run(["docker", "rm", "-f", container])


def read_file(volume: str, path: str) -> str:
    result = checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--read-only",
            "--mount", f"type=volume,src={volume},dst=/wallet,readonly", "--entrypoint", "/bin/bash", IMAGE,
            "-c", f"cat /wallet/{path}",
        ]
    )
    return result.stdout.decode().strip()


def decrypt_archive(path: Path) -> bytes:
    result = checked(
        [
            "docker", "run", "--pull=never", "--rm", "-i", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--security-opt", "no-new-privileges:true", "--user", "0:0",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-e", "GNUPGHOME=/tmp/gpg",
            "--mount", f"type=bind,src={path.resolve()},dst=/archive,readonly", "--entrypoint", "/bin/bash", IMAGE,
            "-c", "mkdir -m 700 /tmp/gpg && gpg --no-options --batch --quiet --pinentry-mode loopback --passphrase-fd 0 --decrypt /archive",
        ],
        input_bytes=(PASSWORD + "\n").encode(),
    )
    return result.stdout


def test_backup_restore() -> None:
    source = resource("source")
    target = resource("target")
    snapshot = resource("snapshot")
    try:
        for volume in (source, target, snapshot):
            create_volume(volume)
        initialize_volume(source, "wallet-A")
        with tempfile.TemporaryDirectory(prefix="ecd-backup-format-") as temporary:
            archive_path = Path(temporary) / "wallet.ecd.gpg"
            create_archive(source, archive_path)
            assert archive_path.stat().st_mode & 0o777 == 0o600
            plaintext = decrypt_archive(archive_path)
            with tarfile.open(fileobj=io.BytesIO(plaintext), mode="r:gz") as archive:
                manifest_file = archive.extractfile("manifest.json")
                config_file = archive.extractfile("payload/config")
                assert manifest_file is not None and config_file is not None
                manifest = json.loads(manifest_file.read())
                config = config_file.read().decode()
                assert manifest["format"] == "ecd-wallet-backup"
                assert manifest["network"] == "mainnet"
                assert CONFIG_SECRET not in config
                assert "rpcpassword" not in config
                assert all(member.isfile() for member in archive.getmembers())

            valid = verify_archive(source, archive_path)
            assert valid.returncode == 0, valid.stderr.decode(errors="replace")
            wrong_password = verify_archive(source, archive_path, "wrong-password")
            assert wrong_password.returncode != 0

            restored = restore_archive(target, archive_path)
            assert restored.returncode == 0, restored.stderr.decode(errors="replace")
            assert read_file(target, "wallets/default_wallet") == "wallet-A"
            assert "rpcpassword" not in read_file(target, "config")
            assert_runtime_tree_is_usable(target)
            assert_real_runtime_stays_up(target)

            initialize_volume(target, "wallet-before-replace")
            replaced = replace_archive(target, archive_path)
            assert replaced.returncode == 0, replaced.stderr.decode(errors="replace")
            assert read_file(target, "wallets/default_wallet") == "wallet-A"
            assert_runtime_tree_is_usable(target)
            assert read_file(source, "wallets/default_wallet") == "wallet-A"

            checked(
                base_helper(source, ["snapshot", "/extra"], volume_readonly=True, extra_volume=snapshot),
            )
            checked(
                [
                    "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", f"type=volume,src={snapshot},dst=/extra", "--entrypoint", "/bin/bash", IMAGE,
                    "-c", "chown -R 0:0 /extra/wallets",
                ]
            )
            checked(
                [
                    "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "0:0",
                    "--mount", f"type=volume,src={source},dst=/wallet", "--entrypoint", "/bin/bash", IMAGE,
                    "-c", "printf 'wallet-mutated\\n' > /wallet/wallets/default_wallet && chown 10001:10001 /wallet/wallets/default_wallet",
                ]
            )
            checked(base_helper(source, ["restore-snapshot", "/extra"], extra_volume=snapshot, extra_readonly=True))
            assert read_file(source, "wallets/default_wallet") == "wallet-A"
            assert_runtime_tree_is_usable(source)

            traversal = Path(temporary) / "traversal.tar.gz"
            manifest = {
                "format": "ecd-wallet-backup", "format_version": 1,
                "electron_cash_version": VERSION, "network": "mainnet", "entries": [],
            }
            with tarfile.open(traversal, "w:gz") as archive:
                encoded = (json.dumps(manifest) + "\n").encode()
                info = tarfile.TarInfo("manifest.json")
                info.size = len(encoded)
                archive.addfile(info, io.BytesIO(encoded))
                bad = tarfile.TarInfo("payload/../escape")
                bad.size = 0
                archive.addfile(bad, io.BytesIO())
            malicious = run(
                [
                    "docker", "run", "--pull=never", "--rm", "--network", "none", "--read-only", "--user", "10001:10001",
                    "--mount", f"type=volume,src={snapshot},dst=/wallet", "--mount", f"type=bind,src={traversal.resolve()},dst=/archive,readonly",
                    "-e", "BACKUP_NETWORK=mainnet", "-e", f"EC_VERSION={VERSION}", "--entrypoint", "/opt/electroncash-venv/bin/python", IMAGE,
                    "/home/electroncash/backup_tool.py", "restore", "/archive", "/wallet",
                ]
            )
            assert malicious.returncode != 0
            assert read_file(snapshot, "wallets/default_wallet") == "wallet-A"
            print("PASS encrypted archive, secret scrubbing, safe replace/restore ownership, source immutability, and rollback copy")
    finally:
        for volume in (source, target, snapshot):
            remove_volume(volume)


if __name__ == "__main__":
    test_backup_restore()
