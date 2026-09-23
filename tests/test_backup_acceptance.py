#!/usr/bin/env python3
"""Disposable real-Docker acceptance for the public backup experience."""

from __future__ import annotations

import hashlib
import io
import json
import os
import signal
import shutil
import subprocess
import tarfile
import tempfile
import time
import uuid
from pathlib import Path

from test_support import electron_cash_image, unique_project, unique_resource


ROOT = Path(__file__).resolve().parents[1]
IMAGE = electron_cash_image()
VERSION = os.environ.get("EC_VERSION", "4.4.6")
PASSWORD = "synthetic-acceptance-password"


def run(command: list[str], *, cwd: Path, input_text: str | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=cwd, input=input_text, text=True, capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, cwd: Path, input_text: str | None = None, timeout: int = 180) -> subprocess.CompletedProcess[str]:
    result = run(command, cwd=cwd, input_text=input_text, timeout=timeout)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result


def create_volume(name: str) -> None:
    checked(["docker", "volume", "create", "--label", "com.bchforge.acceptance=true", name], cwd=ROOT)


def remove_volume(name: str) -> None:
    run(["docker", "volume", "rm", "-f", name], cwd=ROOT)


def rollback_volumes() -> set[str]:
    result = run(
        ["docker", "volume", "ls", "--filter", "label=com.bchforge.electron-cash-docker.managed=rollback", "-q"],
        cwd=ROOT,
    )
    return set(result.stdout.splitlines())


def initialize_volume(name: str, sentinel: str, *, healthy: bool) -> None:
    health_command = "printf 'ok\\n' > /wallet/wallets/health-ok && " if healthy else ""
    command = (
        "mkdir -p /wallet/wallets && "
        "printf 'electron-cash-docker-v0.1\\n' > /wallet/.electron-cash-docker && "
        "printf '{\"auto_connect\":true}\\n' > /wallet/config && "
        f"printf '{sentinel}\\n' > /wallet/wallets/default_wallet && "
        + health_command
        + "chown -R 10001:10001 /wallet && chmod 700 /wallet && "
        "find /wallet -type f -exec chmod 600 {} +"
    )
    checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "0:0",
            "--mount", f"type=volume,src={name},dst=/wallet", "--entrypoint", "/bin/bash", IMAGE, "-c",
            command,
        ],
        cwd=ROOT,
    )


def mutate_volume(name: str, sentinel: str, *, healthy: bool = True) -> None:
    health_command = "printf 'ok\\n' > /wallet/wallets/health-ok && " if healthy else "rm -f /wallet/wallets/health-ok && "
    checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--user", "0:0",
            "--mount", f"type=volume,src={name},dst=/wallet", "--entrypoint", "/bin/bash", IMAGE, "-c",
            f"printf '{sentinel}\\n' > /wallet/wallets/default_wallet && " + health_command +
            "chown 10001:10001 /wallet/wallets/default_wallet /wallet/wallets/health-ok 2>/dev/null || true",
        ],
        cwd=ROOT,
    )


def wallet_value(name: str) -> str:
    result = checked(
        [
            "docker", "run", "--pull=never", "--rm", "--network", "none", "--read-only",
            "--mount", f"type=volume,src={name},dst=/wallet,readonly", "--entrypoint", "/bin/bash", IMAGE,
            "-c", "cat /wallet/wallets/default_wallet",
        ],
        cwd=ROOT,
    )
    return result.stdout.strip()


def direct_create(volume: str, output: Path) -> None:
    result = subprocess.run(
        [
            "docker", "run", "--pull=never", "--rm", "-i", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--cap-add=CHOWN", "--cap-add=FOWNER",
            "--security-opt", "no-new-privileges:true", "--user", "0:0", "--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
            "--mount", f"type=volume,src={volume},dst=/wallet,readonly", "-e", "BACKUP_NETWORK=mainnet",
            "-e", f"EC_VERSION={VERSION}", "--entrypoint", "/home/electroncash/backup.sh", IMAGE, "create", "--stdout",
        ],
        cwd=ROOT,
        input=(PASSWORD + "\n").encode(),
        capture_output=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    output.write_bytes(result.stdout)
    output.chmod(0o600)


def manifest_digest(archive: Path) -> str:
    result = subprocess.run(
        [
            "docker", "run", "--pull=never", "--rm", "-i", "--network", "none", "--read-only",
            "--cap-drop=ALL", "--cap-add=DAC_OVERRIDE", "--security-opt", "no-new-privileges:true", "--user", "0:0",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-e", "GNUPGHOME=/tmp/gpg",
            "--mount", f"type=bind,src={archive.resolve()},dst=/archive,readonly", "--entrypoint", "/bin/bash", IMAGE,
            "-c", "mkdir -m 700 /tmp/gpg && gpg --no-options --batch --quiet --pinentry-mode loopback --passphrase-fd 0 --decrypt /archive",
        ],
        cwd=ROOT,
        input=(PASSWORD + "\n").encode(),
        capture_output=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout.decode(errors="replace") + result.stderr.decode(errors="replace"))
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:gz") as payload:
        member = payload.extractfile("manifest.json")
        if member is None:
            raise AssertionError("backup has no manifest")
        manifest = json.loads(member.read())
    return hashlib.sha256((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()).hexdigest()


def write_fixture(project: Path, volume: str) -> None:
    (project / "scripts").mkdir(parents=True)
    shutil.copy2(ROOT / "scripts/backup.sh", project / "scripts/backup.sh")
    project.joinpath("scripts/backup.sh").chmod(0o755)
    (project / "docker-compose.yml").write_text(
        f"""services:
  electron-cash:
    image: {IMAGE}
    entrypoint: [/bin/bash]
    command: [-c, 'exec sleep infinity']
    healthcheck:
      test: [CMD-SHELL, 'test -f /home/electroncash/.electron-cash/wallets/health-ok']
      interval: 1s
      timeout: 1s
      retries: 1
      start_period: 1s
    volumes:
      - electron-cash-data:/home/electroncash/.electron-cash
volumes:
  electron-cash-data:
    name: ${{ECD_WALLET_VOLUME}}
""",
        encoding="utf-8",
    )
    project.joinpath(".env").write_text(
        f"ECD_WALLET_VOLUME={volume}\nTESTNET4=false\n",
        encoding="utf-8",
    )


def public_environment(project: Path, state_home: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "BACKUP_DIR": str(project / "backups"),
            "COMPOSE_PROJECT_NAME": project.name,
            "EC_VERSION": VERSION,
            "IMAGE": IMAGE,
            "XDG_STATE_HOME": str(state_home),
        }
    )
    return environment


def run_public(project: Path, operation: str, name: str, state_home: Path, input_text: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(project / "scripts/backup.sh"), operation, name],
        cwd=project,
        env=public_environment(project, state_home),
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )


def interrupt_restore_after_marker(project: Path, name: str, state_home: Path) -> None:
    process = subprocess.Popen(
        [str(project / "scripts/backup.sh"), "restore", name],
        cwd=project,
        env=public_environment(project, state_home),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    assert process.stdin is not None
    process.stdin.write(f"y\n{PASSWORD}\n")
    process.stdin.flush()
    pending = state_home / "electron-cash-docker/restore-pending"
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline and not pending.exists():
        if process.poll() is not None:
            output = (process.stdout.read() if process.stdout else "") + (process.stderr.read() if process.stderr else "")
            raise AssertionError(f"restore exited before writing its marker: {output}")
        time.sleep(0.1)
    assert pending.is_file(), "restore did not reach the destructive marker boundary"
    os.killpg(process.pid, signal.SIGKILL)
    process.wait(timeout=30)


def wait_for_restore_helpers(project: Path, volume: str, timeout: int = 60) -> None:
    compose_container = run(
        ["docker", "compose", "-p", project.name, "ps", "-q", "electron-cash"],
        cwd=project,
    ).stdout.strip()
    deadline = time.monotonic() + timeout
    users: set[str] = set()
    while time.monotonic() < deadline:
        users = set(run(["docker", "ps", "-q", "--filter", f"volume={volume}"], cwd=ROOT).stdout.splitlines())
        if users <= ({compose_container} if compose_container else set()):
            return
        time.sleep(1)
    raise AssertionError(f"restore helper containers still use {volume}: {users}")


def wait_for_healthy(project: Path, timeout: int = 60) -> None:
    deadline = time.monotonic() + timeout
    compose = ["docker", "compose", "-p", project.name]
    while time.monotonic() < deadline:
        container = run([*compose, "ps", "-q", "--status", "running", "electron-cash"], cwd=project).stdout.strip()
        if container:
            state = run(
                ["docker", "inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", container],
                cwd=ROOT,
            ).stdout.strip()
            if state == "running|healthy":
                return
            if state.endswith("|unhealthy") or state.startswith(("exited|", "dead|")):
                raise AssertionError(f"service is not healthy: {state}")
        time.sleep(1)
    raise AssertionError("timed out waiting for healthy service")


def service_running(project: Path) -> bool:
    return bool(run(["docker", "compose", "-p", project.name, "ps", "-q", "--status", "running", "electron-cash"], cwd=project).stdout.strip())


def assert_no_restore_artifacts(state_home: Path, baseline: set[str]) -> None:
    state_dir = state_home / "electron-cash-docker"
    if state_dir.exists():
        assert not list(state_dir.iterdir()), list(state_dir.iterdir())
    assert rollback_volumes() == baseline


def test_backup_acceptance() -> None:
    project_name = unique_project("backup-simple")
    active = unique_resource("active")
    bad_source = unique_resource("bad-source")
    project: Path | None = None
    rollback_before = rollback_volumes()
    try:
        create_volume(active)
        create_volume(bad_source)
        initialize_volume(active, "wallet-original", healthy=True)
        initialize_volume(bad_source, "wallet-bad", healthy=False)
        with tempfile.TemporaryDirectory(prefix="ecd-backup-acceptance-") as temporary:
            root = Path(temporary)
            project = root / project_name
            project.mkdir()
            state_home = root / "state"
            write_fixture(project, active)
            compose = ["docker", "compose", "-p", project.name]
            try:
                checked([*compose, "up", "-d", "electron-cash"], cwd=project)
                wait_for_healthy(project)

                backup = run_public(project, "backup", "known-good", state_home, f"{PASSWORD}\n{PASSWORD}\n")
                assert backup.returncode == 0, backup.stdout + backup.stderr
                archive = project / "backups/known-good.ecd.gpg"
                assert archive.is_file()
                source_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
                source_manifest_digest = manifest_digest(archive)
                assert service_running(project)

                existing = run_public(project, "backup", "known-good", state_home, "")
                assert existing.returncode != 0
                assert hashlib.sha256(archive.read_bytes()).hexdigest() == source_digest
                assert manifest_digest(archive) == source_manifest_digest

                mutate_volume(active, "wallet-mutated")
                restored = run_public(project, "restore", "known-good", state_home, f"y\n{PASSWORD}\n")
                assert restored.returncode == 0, restored.stdout + restored.stderr
                assert wallet_value(active) == "wallet-original"
                assert service_running(project)
                wait_for_healthy(project)
                assert hashlib.sha256(archive.read_bytes()).hexdigest() == source_digest
                assert manifest_digest(archive) == source_manifest_digest
                assert_no_restore_artifacts(state_home, rollback_before)

                checked([*compose, "stop", "electron-cash"], cwd=project)
                mutate_volume(active, "wallet-stopped-mutation")
                stopped_restore = run_public(project, "restore", "known-good", state_home, f"y\n{PASSWORD}\n")
                assert stopped_restore.returncode == 0, stopped_restore.stdout + stopped_restore.stderr
                assert wallet_value(active) == "wallet-original"
                assert not service_running(project)
                assert hashlib.sha256(archive.read_bytes()).hexdigest() == source_digest
                assert manifest_digest(archive) == source_manifest_digest
                assert_no_restore_artifacts(state_home, rollback_before)

                mutate_volume(active, "wallet-before-interruption", healthy=True)
                checked([*compose, "up", "-d", "electron-cash"], cwd=project)
                wait_for_healthy(project)
                interrupt_restore_after_marker(project, "known-good", state_home)
                assert (state_home / "electron-cash-docker/restore-pending").is_file()
                wait_for_restore_helpers(project, active)
                recovery_backup = run_public(project, "backup", "after-interruption", state_home, f"{PASSWORD}\n{PASSWORD}\n")
                assert recovery_backup.returncode == 0, recovery_backup.stdout + recovery_backup.stderr
                assert wallet_value(active) == "wallet-before-interruption"
                assert service_running(project)
                wait_for_healthy(project)
                assert hashlib.sha256(archive.read_bytes()).hexdigest() == source_digest
                assert manifest_digest(archive) == source_manifest_digest
                assert_no_restore_artifacts(state_home, rollback_before)

                with tempfile.TemporaryDirectory(prefix="ecd-bad-archive-") as archive_temp:
                    bad_archive = Path(archive_temp) / "bad.ecd.gpg"
                    direct_create(bad_source, bad_archive)
                    shutil.copy2(bad_archive, project / "backups/bad.ecd.gpg")
                mutate_volume(active, "wallet-before-failure", healthy=True)
                checked([*compose, "up", "-d", "electron-cash"], cwd=project)
                wait_for_healthy(project)
                bad_path = project / "backups/bad.ecd.gpg"
                bad_digest = hashlib.sha256(bad_path.read_bytes()).hexdigest()
                bad_manifest_digest = manifest_digest(bad_path)

                failed = run_public(project, "restore", "bad", state_home, f"y\n{PASSWORD}\n")
                assert failed.returncode != 0, failed.stdout + failed.stderr
                combined = failed.stdout + failed.stderr
                assert "Restore failed" in combined
                assert "Previous wallet restored" in combined
                assert wallet_value(active) == "wallet-before-failure"
                assert service_running(project)
                wait_for_healthy(project)
                assert hashlib.sha256(bad_path.read_bytes()).hexdigest() == bad_digest
                assert manifest_digest(bad_path) == bad_manifest_digest
                assert_no_restore_artifacts(state_home, rollback_before)
                print("PASS running/stopped backup state, immutable source hash/manifest, sentinel restore, forced health rollback, and cleanup")
            finally:
                run([*compose, "down", "--remove-orphans"], cwd=project, timeout=120)
    finally:
        remove_volume(active)
        remove_volume(bad_source)
        for volume in rollback_volumes() - rollback_before:
            remove_volume(volume)


if __name__ == "__main__":
    test_backup_acceptance()
