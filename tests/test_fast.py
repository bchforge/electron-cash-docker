#!/usr/bin/env python3
"""Static checks selected by the canonical fast validation mode."""

from __future__ import annotations

import compileall
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import test_compose_isolation
import test_electron_cash_version
import test_novnc_sharing
import test_novnc_websocket_heartbeat
import test_plugin_distribution
import test_tor_proxy


def main() -> None:
    assert compileall.compile_dir(str(ROOT / "docker"), quiet=1)
    assert compileall.compile_dir(str(ROOT / "tests"), quiet=1)
    test_compose_isolation.main()
    test_electron_cash_version.test_declared_pins()
    test_novnc_sharing.test_x11vnc_uses_shared_server_mode()
    test_novnc_websocket_heartbeat.test_websockify_uses_30_second_heartbeat()
    test_novnc_websocket_heartbeat.test_novnc_uses_application_keepalive()
    test_plugin_distribution.test_manifest_schema_and_verification_wiring()
    test_plugin_distribution.test_manifest_rejects_missing_and_malformed_hashes()
    test_plugin_distribution.test_incorrect_zip_hash_fails_closed()
    test_plugin_distribution.test_runtime_plugin_path_has_no_download_or_latest_fallback()
    test_tor_proxy.test_static_provenance()
    print("PASS fast static regression checks")


if __name__ == "__main__":
    main()
