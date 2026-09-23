#!/usr/bin/env python3
"""Ensure reconcile and rollback failures are explicit and non-silent."""

from __future__ import annotations

import importlib.util
import json
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("caddy_ban", ROOT / "docker/fail2ban/caddy_ban.py")
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="ecd-caddy-ban-failure-") as directory:
        state_dir = Path(directory)
        MODULE.STATE_DIR = state_dir
        MODULE.STATE_FILE = state_dir / "banlist.json"
        MODULE.SNIPPET_FILE = state_dir / "banlist.caddy"
        MODULE.CADDYFILE = state_dir / "Caddyfile"
        MODULE.FAILURE_FILE = state_dir / "protection-error.json"
        MODULE.LOCK_FILE = state_dir / ".lock"
        old = [{"client_ip": "203.0.113.10", "peer_ip": "203.0.113.10", "mode": "direct", "packet_drop": True}]
        MODULE.STATE_FILE.write_text(json.dumps({"version": 1, "bans": old}) + "\n")
        MODULE.SNIPPET_FILE.write_text(MODULE.render_snippet(old))
        MODULE.CADDYFILE.write_text("# candidate\n")

        calls = 0

        def firewall(_bans):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise RuntimeError("synthetic rollback firewall failure")

        MODULE._reconcile_firewall = firewall
        MODULE.load_caddyfile = lambda: (_ for _ in ()).throw(RuntimeError("synthetic Caddy reload failure"))
        candidate = [{"client_ip": "198.51.100.20", "peer_ip": "198.51.100.20", "mode": "direct", "packet_drop": True}]
        try:
            MODULE.reconcile_locked(candidate)
        except MODULE.ReconcileError as error:
            message = str(error)
            assert "reconcile failed" in message
            assert "rollback failed" in message
            assert "synthetic rollback firewall failure" in message
            assert "synthetic Caddy reload failure" in message
        else:
            raise AssertionError("reconcile failure was swallowed")

        assert json.loads(MODULE.STATE_FILE.read_text()) == {"version": 1, "bans": old}
        assert MODULE.SNIPPET_FILE.read_text() == MODULE.render_snippet(old)
    print("PASS explicit reconcile failure and rollback-failure reporting")


if __name__ == "__main__":
    main()
