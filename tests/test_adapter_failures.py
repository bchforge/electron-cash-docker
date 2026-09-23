#!/usr/bin/env python3
"""Exercise visible caddy-log-adapter malformed and systemic failure paths."""

from __future__ import annotations

import importlib.util
import os
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(directory: Path):
    os.environ["CADDY_ACCESS_LOG"] = str(directory / "access.log")
    os.environ["FAIL2BAN_PARSED_LOG"] = str(directory / "parsed.log")
    os.environ["CADDY_IDENTITY_MAP"] = str(directory / "identity.json")
    os.environ["CADDY_TRUSTED_PROXY_FILE"] = str(directory / "trusted.txt")
    (directory / "access.log").touch()
    (directory / "trusted.txt").write_text("203.0.113.0/24\n")
    spec = importlib.util.spec_from_file_location("caddy_adapter", ROOT / "docker/fail2ban/caddy-log-adapter.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ecd-adapter-failure-") as directory_name:
        directory = Path(directory_name)
        module = load(directory)
        module.process("not-json")
        module.process('{"status":401,"request":{}}')
        assert module.malformed_lines == 2

        (directory / "trusted.txt").write_text("not-a-cidr\n")
        try:
            module.process('{"ts":1,"status":401,"request":{"remote_ip":"203.0.113.5","client_ip":"198.51.100.5"}}')
        except RuntimeError as error:
            assert "trusted-proxy policy" in str(error)
        else:
            raise AssertionError("systemic trusted-proxy policy failure was swallowed")

        module.raw_path = directory / "missing.log"
        clock = iter((0.0, 31.0))
        module.time.monotonic = lambda: next(clock)
        module.time.sleep = lambda _seconds: None
        try:
            module.follow()
        except RuntimeError as error:
            assert "configured Caddy log is unavailable" in str(error)
        else:
            raise AssertionError("missing configured Caddy log did not fail visibly")
    print("PASS bounded malformed-line logging and visible adapter systemic failures")


if __name__ == "__main__":
    main()
