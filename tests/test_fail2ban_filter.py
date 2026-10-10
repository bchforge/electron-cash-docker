#!/usr/bin/env python3
"""Run fail2ban-regex against the actual Caddy JSON filter with adversarial lines."""

from __future__ import annotations

import json
import os
import re
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("FAIL2BAN_IMAGE", "electron-cash-docker-fail2ban:1.0")
FILTER = ROOT / "docker/fail2ban/filter.d/caddy-basicauth.conf"


def record(status: int, *, client_ip: str | None, remote_ip: str | None = None, uri: str = "/") -> str:
    request = {
        "remote_ip": remote_ip or client_ip or "172.20.0.10",
        "client_ip": client_ip,
        "uri": uri,
        "headers": {"Authorization": ["REDACTED"]},
    }
    if client_ip is None:
        request.pop("client_ip")
    return json.dumps({"status": status, "request": request})


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ecd-fail2ban-regex-") as directory:
        log = Path(directory) / "access.log"
        log.write_text(
            "\n".join(
                (
                    record(401, client_ip="198.51.100.20"),
                    record(401, client_ip="2001:db8::20"),
                    record(401, client_ip="198.51.100.21", uri="/auth/login?next=/auth/gui-session"),
                    record(401, client_ip="198.51.100.30", uri="/auth/gui-session"),
                    record(401, client_ip="198.51.100.31", uri="/auth/gui-session?probe=1"),
                    record(200, client_ip="198.51.100.20"),
                    record(401, client_ip=None, uri="/fake-203.0.113.123"),
                    "not-json 401 client_ip=203.0.113.123",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                "docker",
                "run",
                "--pull=never",
                "--rm",
                "--network",
                "none",
                "--mount",
                f"type=bind,src={log},dst=/tmp/access.log,readonly",
                "--mount",
                f"type=bind,src={FILTER},dst=/tmp/filter.conf,readonly",
                "--entrypoint",
                "fail2ban-regex",
                IMAGE,
                "--print-all-matched",
                "/tmp/access.log",
                "/tmp/filter.conf",
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            timeout=120,
        )
        output = result.stdout + result.stderr
        assert result.returncode == 0, output
        assert re.search(r"Failregex:\s+3 total", output), output
        matched = output.split("|- Matched line(s):", 1)[-1].split("|- Missed line(s):", 1)[0]
        assert "203.0.113.123" not in matched, output
        assert "198.51.100.21" in matched and "198.51.100.30" not in matched and "198.51.100.31" not in matched, output
    adapter = (ROOT / "docker/fail2ban/caddy-log-adapter.py").read_text(encoding="utf-8")
    assert "parsed_address != remote" in adapter
    print("PASS fail2ban-regex client_ip/spoof checks, passive stale-cookie non-ban and unchanged login enforcement")


if __name__ == "__main__":
    main()
