#!/usr/bin/env python3
"""Focused negative controls for the optional Ledger virtual harness."""
import json
import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_ledger_virtual as harness


class HarnessChecks(unittest.TestCase):
    def hardware_model(self):
        from test_electron_cash_version import EXPECTED_VERSION, EXPECTED_COMMIT, EXPECTED_ARCHIVE_SHA256
        hardening = {"read_only": True, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
        return {"services": {
            "electron-cash": {**hardening,
                "build": {"args": {"HW_SUPPORT": "1", "EC_VERSION": EXPECTED_VERSION,
                    "EC_COMMIT": EXPECTED_COMMIT, "EC_ARCHIVE_SHA256": EXPECTED_ARCHIVE_SHA256}},
                "environment": {"HW_SUPPORT": "1", "ECD_GUI_OVERLAY": "true", "HW_USB_GID": "10001"},
                "devices": [{"source": "/dev/bus/usb", "target": "/dev/bus/usb", "permissions": "rwm"}],
                "device_cgroup_rules": ["c 189:* rw"]},
            "gateway": {**hardening}}}

    def test_current_hardware_contract_without_historical_git(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = harness.Validation(Path(directory))
            with patch.object(runner, "command", return_value=json.dumps(self.hardware_model())) as command:
                runner.hardware_audit()
            self.assertEqual(command.call_count, 1)
            self.assertEqual(command.call_args.args[0][:2], ["docker", "compose"])
            record = json.loads((Path(directory) / "ledger-contract.json").read_text())
            self.assertEqual(record["status"], "PASS")
            self.assertNotIn("baseline", record)

    def test_current_hardware_contract_rejects_drift(self):
        original = self.hardware_model()
        for service, key, value in (
                ("electron-cash", "devices", []),
                ("electron-cash", "device_cgroup_rules", ["c *:* rw"]),
                ("electron-cash", "privileged", True),
                ("electron-cash", "read_only", False),
                ("gateway", "devices", original["services"]["electron-cash"]["devices"]),
                ("gateway", "security_opt", [])):
            with self.subTest(service=service, key=key), tempfile.TemporaryDirectory() as directory:
                model = copy.deepcopy(original)
                model["services"][service][key] = value
                runner = harness.Validation(Path(directory))
                with patch.object(runner, "command", return_value=json.dumps(model)):
                    with self.assertRaisesRegex(RuntimeError, "current Ledger hardware contract failed"):
                        runner.hardware_audit()
                self.assertEqual(json.loads((Path(directory) / "ledger-contract.json").read_text())["status"], "FAIL")

    def test_corrupt_cache_is_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = Path(directory)
            digest = harness.hashlib.sha256(b"expected").hexdigest()
            (cache / digest).write_bytes(b"corrupt")
            with patch.object(harness, "CACHE", cache), patch.object(harness.urllib.request, "urlopen",
                    return_value=harness.io.BytesIO(b"wrong-download")):
                with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                    harness.verified_download("https://test.invalid/fixture", digest)

    def test_manifest_detects_tampering_and_non_pass_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            names = ("result", "speculos", "ledger-app", "transport", "plugin", "derivation", "reconnect",
                     "ledger-contract", "cleanup")
            for name in names:
                (root / (name + ".json")).write_text('{"status":"PASS"}')
            def seal():
                manifest = {"files": {name + ".json": harness.ci.sha256_file(root / (name + ".json")) for name in names}}
                (root / "manifest.json").write_text(json.dumps(manifest))
                (root / "manifest.sha256").write_text(harness.ci.sha256_file(root / "manifest.json") + "  manifest.json\n")
            seal()
            self.assertEqual(harness.verify_evidence(root)["status"], "PASS")
            (root / "cleanup.json").write_text('{"status":"FAIL"}')
            self.assertEqual(harness.verify_evidence(root)["status"], "FAIL")
            seal()  # Even internally consistent hashes cannot turn FAIL into PASS.
            self.assertEqual(harness.verify_evidence(root)["status"], "FAIL")

    def test_auto_removed_container_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = harness.Validation(Path(directory))
            runner.names = ["already-auto-removed"]
            with patch.object(runner, "command", side_effect=["[]", "", "", ""]):
                runner.cleanup()
            self.assertEqual(json.loads((Path(directory) / "cleanup.json").read_text())["status"], "PASS")

    def test_foreign_container_is_preserved_and_fails_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = harness.Validation(Path(directory))
            runner.names = ["foreign"]
            foreign = json.dumps([{"Config": {"Labels": {harness.OWNER_LABEL: "another-owner"}}}])
            with patch.object(runner, "command", side_effect=[foreign, "", "", ""]) as command:
                with self.assertRaisesRegex(RuntimeError, "cleanup failed"):
                    runner.cleanup()
            self.assertFalse(any("rm" in call.args[0] or "stop" in call.args[0] for call in command.call_args_list))


def main():
    result = unittest.TextTestRunner().run(unittest.defaultTestLoader.loadTestsFromTestCase(HarnessChecks))
    if not result.wasSuccessful():
        raise AssertionError("Ledger harness checks failed")


if __name__ == "__main__":
    main()
