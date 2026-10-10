#!/usr/bin/env python3
"""Static checks selected by the canonical fast validation mode."""

from __future__ import annotations

import compileall
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

import test_compose_isolation
import test_cloudflare_cidrs
import test_auth_config
import test_auth_session
import test_compose_network
import test_electron_cash_version
import test_gitlab_status_adapter
import test_novnc_sharing
import test_novnc_websocket_heartbeat
import test_local_tooling
import test_plugin_distribution
import test_product_version
import test_runtime_dependencies
import test_security_policy
import test_tor_proxy
import test_network_selection
import test_platform_runner
import test_docker_ownership
import test_ci_protection_preflight
import test_disk_budget
import test_build_reuse
import test_mac_gui
import test_ci_required
import test_docs
import test_ledger_virtual_harness
import test_caddy_version
import test_release_security


def main() -> None:
    assert compileall.compile_dir(str(ROOT / "docker"), quiet=1)
    assert compileall.compile_dir(str(ROOT / "tests"), quiet=1)
    test_compose_isolation.main()
    test_compose_network.main()
    test_network_selection.main()
    test_platform_runner.main()
    test_docker_ownership.main()
    test_ci_protection_preflight.main()
    test_disk_budget.main()
    test_build_reuse.main()
    test_mac_gui.main()
    test_ci_required.main()
    test_auth_config.static_main()
    test_auth_session.main()
    test_cloudflare_cidrs.main()
    test_electron_cash_version.test_declared_pins()
    test_novnc_sharing.test_x11vnc_uses_shared_server_mode()
    test_novnc_websocket_heartbeat.test_websockify_uses_30_second_heartbeat()
    test_novnc_websocket_heartbeat.test_novnc_uses_application_keepalive()
    test_local_tooling.main()
    test_gitlab_status_adapter.main()
    test_plugin_distribution.test_manifest_schema_and_verification_wiring()
    test_plugin_distribution.test_manifest_rejects_missing_and_malformed_hashes()
    test_plugin_distribution.test_incorrect_zip_hash_fails_closed()
    test_plugin_distribution.test_runtime_plugin_path_has_no_download_or_latest_fallback()
    test_product_version.test_runtime_version_is_configured()
    test_runtime_dependencies.test_manifest_is_exact_runtime_authority()
    test_security_policy.main()
    test_tor_proxy.test_static_provenance()
    test_docs.main()
    test_ledger_virtual_harness.main()
    test_caddy_version.static_main()
    test_release_security.static_main()
    print("PASS fast static regression checks")


if __name__ == "__main__":
    main()
