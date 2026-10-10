#!/usr/bin/env python3
"""Focused false-PASS/cleanup checks; no GUI runtime required."""
import contextlib
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import test_linux_x11 as x11


class HarnessTests(unittest.TestCase):
    def test_synthetic_and_forwarding_rejected(self):
        for name in ("Xvfb", "Xephyr", "offscreen", "minimal", "fake"):
            with self.assertRaisesRegex(x11.native.RunnerError, "rejected"):
                x11.server_identity(":90", 1, "/usr/bin/" + name, [name, ":90"])
        with self.assertRaisesRegex(x11.native.RunnerError, "local Unix"):
            x11.server_identity("localhost:10", 1, "/usr/bin/Xorg", ["Xorg"])

    def test_missing_server_nonpass_and_failure_cleanup(self):
        with tempfile.TemporaryDirectory(dir=x11.STATE / "tasks") as directory:
            evidence = Path(directory)
            (evidence / "command.log").touch()
            test = x11.Validation(evidence)
            with patch.object(test, "preflight"), patch.dict(x11.os.environ, {"DISPLAY": ":999"}), \
                    patch.object(x11, "local_servers", return_value=[]), \
                    patch.object(x11, "drm_blockers", return_value=[]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(test.execute(), 1)
            import json
            result = json.loads((evidence / "result.json").read_text())
            self.assertEqual(result["phase"], "B")
            self.assertEqual(result["classification"], "HOST_X11_FAILURE")
            self.assertIn("no identifiable local X server", result["error"])
            self.assertFalse(test.temp.exists())
            self.assertEqual(json.loads((evidence / "cleanup.json").read_text())["status"], "PASS")

    def test_hung_drm_selects_independent_dummy(self):
        with tempfile.TemporaryDirectory(dir=x11.STATE / "tasks") as directory:
            test = x11.Validation(Path(directory))
            test.env["DISPLAY"] = ":91"
            with patch.object(x11, "drm_blockers", return_value=[{"pid": 1, "state": "D", "stack": "qxl_fence_wait"}]), \
                    patch.object(x11, "local_servers", return_value=[]), \
                    patch.dict(x11.os.environ, {"DISPLAY": ""}), \
                    patch.object(test, "start_xorg", return_value={"server": "Xorg", "driver": "dummy"}) as launch, \
                    patch.object(test, "command", return_value="version number: 11.0"):
                test.display_setup()
                launch.assert_called_once_with("dummy")
                self.assertTrue(test.xserver["xdpyinfo_success"])

    def test_no_qualifying_backends_cannot_pass(self):
        with tempfile.TemporaryDirectory(dir=x11.STATE / "tasks") as directory:
            test = x11.Validation(Path(directory))
            with patch.object(x11, "drm_blockers", return_value=[{"pid": 1}]), \
                    patch.object(x11, "local_servers", return_value=[]), patch.dict(x11.os.environ, {"DISPLAY": ""}), \
                    patch.object(test, "start_xorg", side_effect=x11.native.RunnerError("dummy unavailable")):
                with self.assertRaisesRegex(x11.native.RunnerError, "dummy unavailable"):
                    test.display_setup()

    def test_unique_resources_supported_runner(self):
        first, second = x11.Validation(Path("/unused")), x11.Validation(Path("/unused"))
        self.assertNotEqual(first.project, second.project)
        self.assertTrue(first.env["ECD_WALLET_VOLUME"].startswith(first.project))
        command = x11.native.compose_args("linux-x11", first.project, x11.ROOT / ".env.example")
        self.assertIn(str(x11.ROOT / "docker-compose.gui.yml"), command)
        with patch.object(x11.native, "compose_args", side_effect=RuntimeError("supported runner reached")) as runner:
            with self.assertRaisesRegex(RuntimeError, "supported runner reached"):
                first.launch()
            runner.assert_called_once()

    def test_window_waiter_uses_task_authority(self):
        environment = {"DISPLAY": ":91", "XAUTHORITY": "/task/private-authority"}
        result = x11.subprocess.CompletedProcess([], 0, "  0x123 Electron Cash", "")
        with patch.object(x11.native, "command_result", return_value=result) as command:
            self.assertEqual(x11.native.wait_window(":91", 1, env=environment), "0x123")
            self.assertIs(command.call_args.kwargs["env"], environment)


if __name__ == "__main__":
    unittest.main()
