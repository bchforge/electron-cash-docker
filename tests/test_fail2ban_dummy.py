#!/usr/bin/env python3
"""Exercise the real Fail2Ban jail with a non-firewall dummy action."""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import uuid
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("FAIL2BAN_IMAGE", "electron-cash-docker-fail2ban:1.0")


def run(command: list[str], *, timeout: int = 30, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, text=True, input=input_text, capture_output=True, check=False, timeout=timeout)


def status(name: str) -> str:
    result = run(["docker", "exec", name, "fail2ban-client", "status", "caddy-basicauth"])
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


def wait_for(name: str, predicate, timeout: int = 20) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = status(name)
        if predicate(value):
            return value
        time.sleep(0.25)
    logs = run(["docker", "logs", name])
    raise AssertionError(status(name) + logs.stdout + logs.stderr)


def main() -> None:
    name = f"ecd-fail2ban-dummy-{uuid.uuid4().hex[:10]}"
    with tempfile.TemporaryDirectory(prefix="ecd-fail2ban-dummy-") as directory:
        root = Path(directory)
        log = root / "access.log"
        jail = root / "jail.local"
        log.touch()
        jail.write_text(
            """[DEFAULT]
bantime = 8
findtime = 30
maxretry = 3
backend = polling
action = dummy

[sshd]
enabled = false

[caddy-basicauth]
enabled = true
filter = caddy-basicauth
logpath = /tmp/access.log
""",
            encoding="utf-8",
        )
        try:
            result = run(
                [
                    "docker",
                    "run",
                    "--pull=never",
                    "-d",
                    "--name",
                    name,
                    "--network",
                    "none",
                    "--mount",
                    f"type=bind,src={log},dst=/tmp/access.log",
                    "--mount",
                    f"type=bind,src={jail},dst=/etc/fail2ban/jail.local,readonly",
                    "--entrypoint",
                    "fail2ban-server",
                    IMAGE,
                    "-f",
                    "--logtarget",
                    "stdout",
                ],
                timeout=60,
            )
            assert result.returncode == 0, result.stdout + result.stderr
            wait_for(name, lambda value: "Currently banned:\t0" in value)
            inspection = json.loads(run(["docker", "inspect", name]).stdout)[0]
            assert inspection["HostConfig"]["NetworkMode"] == "none", inspection
            assert not inspection["HostConfig"].get("CapAdd"), inspection

            def failure(index: int, address: str = "198.51.100.20") -> str:
                return f'{{"ts":{time.time()},"status":401,"request":{{"client_ip":"{address}","uri":"/{index}"}}}}\n'

            for index in (1, 2):
                with log.open("a", encoding="utf-8") as output:
                    output.write(failure(index))
                wait_for(name, lambda value, expected=index: f"Total failed:\t{expected}" in value)
                assert "Currently banned:\t0" in status(name)
            with log.open("a", encoding="utf-8") as output:
                output.write(failure(3))
            wait_for(name, lambda value: "Currently banned:\t1" in value)
            banned = status(name)
            assert "198.51.100.20" in banned, banned
            result = run(["docker", "exec", name, "fail2ban-client", "set", "caddy-basicauth", "unbanip", "198.51.100.20"])
            assert result.returncode == 0, result.stdout + result.stderr
            wait_for(name, lambda value: "Currently banned:\t0" in value)

            for index in (4, 5, 6):
                with log.open("a", encoding="utf-8") as output:
                    output.write(failure(index, "198.51.100.21"))
            wait_for(name, lambda value: "Currently banned:\t1" in value)
            assert "198.51.100.21" in status(name)
            wait_for(name, lambda value: "Currently banned:\t0" in value, timeout=15)
            print("PASS real Fail2Ban jail threshold, dummy ban/unban, and natural expiry")
        finally:
            run(["docker", "rm", "-f", name], timeout=60)


if __name__ == "__main__":
    main()
