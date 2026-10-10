#!/usr/bin/env python3
"""Focused false-PASS guards; physical runtime remains an explicit target."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_mac_apple_silicon as mac


class Harness(unittest.TestCase):
    def test_non_darwin_rejected(self):
        with self.assertRaisesRegex(mac.native.RunnerError, "Darwin"):
            mac.require_host("Linux", "arm64")

    def test_non_arm64_rejected(self):
        with self.assertRaisesRegex(mac.native.RunnerError, "arm64"):
            mac.require_host("Darwin", "x86_64")

    def test_missing_xquartz_diagnostic(self):
        with tempfile.TemporaryDirectory() as temp:
            validation = mac.Validation(Path(temp))
            with patch.object(validation, "command", side_effect=["Darwin", "arm64"]), patch.object(Path, "is_file", return_value=False):
                with self.assertRaisesRegex(mac.native.RunnerError, "XQuartz missing"):
                    validation.preflight()

    def test_missing_real_window_rejected(self):
        with patch.object(mac.native, "command_result") as command:
            command.return_value.returncode = 0
            command.return_value.stdout = "root: no wallet window"
            command.return_value.stderr = ""
            with self.assertRaisesRegex(mac.native.RunnerError, "window was not observed"):
                mac.native.wait_window(":0", 0)

    def test_unmapped_window_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            validation = mac.Validation(Path(temp))
            with patch.object(validation, "command", side_effect=[
                    'WM_CLASS = "electron-cash"\nWM_NAME = "Electron Cash"\n_NET_WM_PID(CARDINAL) = 40',
                    "Map State: IsUnMapped"]):
                with self.assertRaisesRegex(mac.native.RunnerError, "not mapped"):
                    validation.window_info("0x800010")

    def test_wrong_wallet_architecture_rejected(self):
        with self.assertRaisesRegex(mac.native.RunnerError, "electron-cash architecture"):
            mac.require_platform("electron-cash", {"Os": "linux", "Architecture": "arm64"}, "linux/amd64")

    def test_wrong_tor_architecture_rejected(self):
        with self.assertRaisesRegex(mac.native.RunnerError, "tor-proxy architecture"):
            mac.require_platform("tor-proxy", {"Os": "linux", "Architecture": "amd64"}, "linux/arm64")

    def test_container_only_success_rejected(self):
        with self.assertRaisesRegex(mac.native.RunnerError, "container-only"):
            mac.require_gui({"container": "PASS", "tor": "PASS"})

    def test_restoration_checked_after_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            validation = mac.Validation(Path(temp))
            before = {"xquartz_running_before": False, "nolisten_tcp_before": "1",
                      "enable_test_extensions_before": "unset", "xhost_access_sha256_before": "unavailable"}
            with patch.object(mac.native, "xquartz_process_name", return_value=None), \
                 patch.object(mac.native, "xhost_access_fingerprint", return_value="unavailable"), \
                 patch.object(mac.native, "command_result") as command, \
                 patch.object(validation, "command", return_value=""):
                command.return_value.stdout = "1"
                validation.cleanup({"status": "PASS"}, before, "interaction failed")
                saved = json.loads((Path(temp) / "cleanup.json").read_text())
                self.assertTrue(saved["xquartz_restored"])
                self.assertEqual(json.loads((Path(temp) / "restart.json").read_text())["status"], "FAIL")
                command.return_value.stdout = "0"
                validation.cleanup({"status": "PASS"}, before, "interaction failed")
                self.assertEqual(json.loads((Path(temp) / "cleanup.json").read_text())["status"], "FAIL")


if __name__ == "__main__":
    unittest.main()
