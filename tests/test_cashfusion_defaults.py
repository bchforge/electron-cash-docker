#!/usr/bin/env python3
"""Behavioral tests for the env-driven CashFusion wallet profile."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMAGE = os.environ.get("ELECTRON_CASH_IMAGE", "electron-cash:4.4.6")
PYTHON = "/opt/electroncash-venv/bin/python"


CODE = r'''
from cashfusion_defaults import (
    CASHFUSION_DEFAULT_PROFILE,
    CashFusionConfigurationError,
    apply_cashfusion_defaults,
    cashfusion_config_from_environment,
)
from electroncash.storage import WalletStorage
from electroncash_plugins.fusion import fusion as fusion_module
from electroncash_plugins.fusion.conf import Conf

expected = {
    "cashfusion_autofuse": False,
    "cashfusion_fusion_mode": "custom",
    "cashfusion_fuse_depth": 3,
    "cashfusion_self_fuse_players": 1,
    "cashfusion_selector": ["count", 10],
    "cashfusion_queued_autofuse": 4,
    "cashfusion_autofuse_only_when_all_confirmed": True,
}
assert CASHFUSION_DEFAULT_PROFILE == expected
assert cashfusion_config_from_environment({}) == {
    "enabled": True,
    "profile": expected,
}
assert cashfusion_config_from_environment({"CASHFUSION_ENABLED": "true"}) == {
    "enabled": True,
    "profile": expected,
}
override_environment = {
    "CASHFUSION_ENABLED": "TRUE",
    "CASHFUSION_AUTO_FUSE": "true",
    "CASHFUSION_FUSION_MODE": "normal",
    "CASHFUSION_FUSE_DEPTH": "7",
    "CASHFUSION_SELF_FUSE_PLAYERS": "2",
    "CASHFUSION_SELECTOR_MODE": "count",
    "CASHFUSION_SELECTOR_COUNT": "25",
    "CASHFUSION_QUEUED_AUTOFUSE": "2",
    "CASHFUSION_AUTOFUSE_CONFIRMED_ONLY": "false",
}
override_profile = cashfusion_config_from_environment(override_environment)
assert override_profile["enabled"] is True
assert override_profile["profile"] == {
    "cashfusion_autofuse": True,
    "cashfusion_fusion_mode": "normal",
    "cashfusion_fuse_depth": 7,
    "cashfusion_self_fuse_players": 2,
    "cashfusion_selector": ["count", 25],
    "cashfusion_queued_autofuse": 2,
    "cashfusion_autofuse_only_when_all_confirmed": False,
}
for selector_environment, expected_selector in (
    (
        {"CASHFUSION_SELECTOR_MODE": "size", "CASHFUSION_SELECTOR_SIZE_BCH": "0.0001"},
        ["size", 10000],
    ),
    (
        {"CASHFUSION_SELECTOR_MODE": "size", "CASHFUSION_SELECTOR_SIZE_BCH": "0.001"},
        ["size", 100000],
    ),
    (
        {"CASHFUSION_SELECTOR_MODE": "fraction", "CASHFUSION_SELECTOR_FRACTION": "1.0"},
        ["fraction", 1.0],
    ),
    (
        {"CASHFUSION_SELECTOR_MODE": "fraction", "CASHFUSION_SELECTOR_FRACTION": "0.5"},
        ["fraction", 0.5],
    ),
):
    parsed = cashfusion_config_from_environment(selector_environment)
    assert parsed["profile"]["cashfusion_selector"] == expected_selector
assert cashfusion_config_from_environment(
    {
        "CASHFUSION_SELECTOR_MODE": "count",
        "CASHFUSION_SELECTOR_COUNT": "10",
        "CASHFUSION_SELECTOR_SIZE_BCH": "0.5",
        "CASHFUSION_SELECTOR_FRACTION": "0.2",
    }
)["profile"]["cashfusion_selector"] == ["count", 10]
for invalid in (
    {"CASHFUSION_AUTO_FUSE": "maybe"},
    {"CASHFUSION_FUSE_DEPTH": "not-an-int"},
    {"CASHFUSION_SELECTOR_MODE": "invalid"},
    {"CASHFUSION_FUSE_DEPTH": "11"},
    {"CASHFUSION_SELECTOR_MODE": "size", "CASHFUSION_SELECTOR_SIZE_BCH": "0"},
    {"CASHFUSION_SELECTOR_MODE": "size", "CASHFUSION_SELECTOR_SIZE_BCH": "0.000000001"},
    {"CASHFUSION_SELECTOR_MODE": "fraction", "CASHFUSION_SELECTOR_FRACTION": "1.1"},
    {"CASHFUSION_SELECTOR_MODE": "fraction", "CASHFUSION_SELECTOR_FRACTION": "foo"},
):
    try:
        cashfusion_config_from_environment(invalid)
    except CashFusionConfigurationError:
        pass
    else:
        raise AssertionError(f"invalid environment accepted: {invalid}")

storage = WalletStorage("/tmp/default_wallet", manual_upgrades=True)
storage.put("wallet_type", "standard")
storage.write()
wallet = type("Wallet", (), {"storage": storage})()
assert "cashfusion_selector" not in storage.data
# The upstream getter has its own fallback; it must not be mistaken for a
# persisted user choice and must not prevent the ECD count default from being written.
assert Conf(wallet).selector != ("count", 10)
assert apply_cashfusion_defaults(wallet) is True
assert {key: storage.get(key) for key in expected} == expected
assert Conf(wallet).autofuse is False
assert Conf(wallet).fusion_mode == "custom"
assert Conf(wallet).fuse_depth == 3
assert Conf(wallet).self_fuse_players == 1
assert Conf(wallet).selector == ("count", 10)
assert Conf(wallet).queued_autofuse == 4
assert Conf(wallet).autofuse_confirmed_only is True
assert apply_cashfusion_defaults(wallet) is False

storage.put("cashfusion_autofuse", True)
storage.put("cashfusion_fuse_depth", 7)
storage.put("cashfusion_selector", ["count", 20])
storage.put("cashfusion_queued_autofuse", 2)
storage.put("cashfusion_autofuse_only_when_all_confirmed", False)
storage.write()
assert apply_cashfusion_defaults(wallet) is False
assert storage.get("cashfusion_autofuse") is True
assert storage.get("cashfusion_fuse_depth") == 7
assert storage.get("cashfusion_selector") == ["count", 20]
assert storage.get("cashfusion_queued_autofuse") == 2
assert storage.get("cashfusion_autofuse_only_when_all_confirmed") is False

# Exercise the real 4.4.6 Wallet Settings dialog so a missing-key profile is
# verified at the same GUI boundary as the reported failure.
import os
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from PyQt5.QtWidgets import QApplication
from electroncash_plugins.fusion import qt as fusion_qt

class MainWindow:
    def get_decimal_point(self):
        return 8

class GuiWallet:
    def __init__(self, storage):
        self.storage = storage
        self._main_window = MainWindow()

    def weak_window(self):
        return self._main_window

gui_storage = WalletStorage("/tmp/gui_wallet", manual_upgrades=True)
gui_storage.put("wallet_type", "standard")
gui_storage.write()
gui_wallet = GuiWallet(gui_storage)
assert apply_cashfusion_defaults(gui_wallet) is True
fusion_qt.select_coins = lambda _wallet: ([], [], 0, False, False)
app = QApplication([])
dialog = fusion_qt.WalletSettingsDialog(None, object(), gui_wallet)
assert dialog.mode_cb.currentText() == "Custom"
assert dialog.chk_fuse_depth.isChecked() is True
assert dialog.sb_fuse_depth.isEnabled() is True
assert dialog.sb_fuse_depth.value() == 3
assert dialog.combo_self_fuse.currentData() == 1
assert dialog.combo_self_fuse.currentText() == "No"
assert dialog.radio_select_count.isChecked() is True
assert dialog.radio_select_size.isChecked() is False
assert dialog.radio_select_fraction.isChecked() is False
assert dialog.sb_selector_count.value() == 10
assert dialog.sb_queued_autofuse.value() == 4
assert dialog.cb_autofuse_only_all_confirmed.isChecked() is True
assert Conf(gui_wallet).autofuse is False
dialog.close()
app.quit()

override_storage = WalletStorage("/tmp/override_wallet", manual_upgrades=True)
override_storage.put("wallet_type", "standard")
override_storage.write()
override_wallet = type("Wallet", (), {"storage": override_storage})()
assert apply_cashfusion_defaults(override_wallet, override_profile["profile"]) is True
assert {
    key: override_storage.get(key) for key in expected
} == override_profile["profile"]

state = object.__new__(fusion_module.Fusion)
state.tor_host = "tor-proxy"
state.tor_port = 9050
state.weak_plugin = None
state.source_wallet_info = {}
state.outputs = []
state.coins = {}
state.keypairs = {}
original_tor_probe = fusion_module.is_tor_port
original_open_connection = fusion_module.open_connection
fusion_module.is_tor_port = lambda _host, _port: False
fusion_module.open_connection = lambda *_args, **_kwargs: (_ for _ in ()).throw(
    AssertionError("CashFusion attempted a direct connection")
)
try:
    state.run()
finally:
    fusion_module.is_tor_port = original_tor_probe
    fusion_module.open_connection = original_open_connection
assert state.status[0] == "failed"
assert "Tor proxy" in state.status[1]
print("CashFusion default profile behavior passed")
'''


def main() -> None:
    result = subprocess.run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "10001:10001",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=64m",
            "--entrypoint",
            PYTHON,
            IMAGE,
            "-c",
            CODE,
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    print("PASS CashFusion env defaults, all selector modes, preservation, and Tor fail-closed behavior")


if __name__ == "__main__":
    main()
