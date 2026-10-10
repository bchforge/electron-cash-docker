#!/usr/bin/env python3
"""Explicit physical Apple Silicon acceptance through the production Mac runner."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import ci  # pyright: ignore[reportMissingImports]
import platform_runner as native  # pyright: ignore[reportMissingImports]

STATE = Path.home() / ".local/state/electron-cash-docker"
CONFIG = (".env.example", "docker-compose.yml", "docker-compose.gui.yml", "scripts/mac-gui.sh",
          "scripts/mac-compose-overlay.py")


def require(condition, message):
    if not condition:
        raise native.RunnerError(message)


def require_host(system, architecture):
    require(system == "Darwin", f"mac-apple-silicon requires Darwin, observed {system}")
    require(architecture == "arm64", f"mac-apple-silicon requires arm64, observed {architecture}")


def require_gui(outcomes):
    require(outcomes.get("gui") == "PASS", "container-only success rejected")


def configuration():
    return ci.sha256_bytes(json.dumps({name: ci.sha256_file(ROOT / name) for name in CONFIG},
                                    sort_keys=True, separators=(",", ":")).encode())


def require_platform(service, image, expected):
    actual = image["Os"] + "/" + image["Architecture"]
    require(actual == expected, f"wrong {service} architecture: {actual}, expected {expected}")
    return actual


class Validation:
    def __init__(self, evidence):
        self.evidence = evidence
        self.env = os.environ.copy()
        self.before = {}
        self.outcomes = {}
        self.inputs = {}
        self.phase = 1
        self.restart_control: Path | None = None
        self.authority_path: Path | None = None

    def write(self, name, value):
        ci.json_write(self.evidence / name, value)

    def command(self, args, timeout=60, check=True):
        result = native.command_result(args, env=self.env, timeout=timeout, check=False)
        with (self.evidence / "command.log").open("a") as log:
            log.write(json.dumps({"command": args, "returncode": result.returncode}) + "\n")
        if check:
            require(result.returncode == 0, f"command failed: {args}: {result.stderr[-1200:]}")
        return result.stdout.strip()

    def preflight(self):
        require_host(self.command(["uname", "-s"]), self.command(["uname", "-m"]))
        require(Path("/Applications/Utilities/XQuartz.app/Contents/Info.plist").is_file(),
                "XQuartz missing: install the supported XQuartz application")
        for name in ("xauth", "xdpyinfo", "xwininfo", "xprop", "xwd", "xdotool"):
            require(shutil.which(name), f"missing X11 utility: {name}")
        docker_binary = Path(shutil.which("docker") or "docker").resolve()
        require("Docker.app/Contents/Resources/bin/docker" in str(docker_binary),
                "canonical physical test requires the installed Docker Desktop CLI binary")
        self.write("host.json", {"system": "Darwin", "architecture": "arm64",
            "sw_vers": self.command(["sw_vers"]), "uname": self.command(["uname", "-a"]),
            "cpu": self.command(["sysctl", "-n", "machdep.cpu.brand_string"]),
            "model": self.command(["sysctl", "-n", "hw.model"]), "synthetic": False})
        self.write("docker.json", {"version": json.loads(self.command(["docker", "version", "--format", "{{json .}}"])),
            "info": json.loads(self.command(["docker", "info", "--format", "{{json .}}"])),
            "compose": self.command(["docker", "compose", "version"]),
            "docker_executable": str(Path(shutil.which("docker") or "docker").resolve())})
        candidate = ci.candidate_identity(self.evidence)
        candidate["configuration_fingerprint"] = configuration()
        self.write("candidate.json", candidate)

    def host(self, info):
        info["enable_test_extensions_before"] = self.command(
            ["defaults", "read", "org.xquartz.X11", "enable_test_extensions"], check=False) or "unset"
        self.before = info
        self.write("xquartz.json", {"before": info, "tools": {n: shutil.which(n) for n in
            ("xdpyinfo", "xwininfo", "xprop", "xauth", "xdotool")},
            "installed_prerequisite": "Homebrew xdotool 4.20260303.1"})

    def build_inputs(self, inputs):
        for descriptor in inputs.values():
            descriptor["input_modes"] = {name: format((Path(descriptor["context"]) / name).stat().st_mode & 0o777, "04o")
                                         for name in descriptor["inputs"]}
        self.inputs = inputs
        self.write("product-inputs.json", inputs)

    def window_info(self, window):
        properties = self.command(["xprop", "-id", window, "WM_CLASS", "WM_NAME", "_NET_WM_PID"])
        geometry = self.command(["xwininfo", "-id", window])
        require("Map State: IsViewable" in geometry, "Electron Cash window is not mapped")
        require("Electron Cash" in properties and "WM_CLASS" in properties,
                "window lacks Electron Cash Qt identity")
        pid = re.search(r"_NET_WM_PID\(CARDINAL\) = (\d+)", properties)
        if pid is None:
            raise native.RunnerError("Qt window lacks process PID")
        return {"id": window, "properties": properties, "geometry": geometry, "pid": int(pid.group(1))}

    def visible(self):
        result = native.command_result(["xdotool", "search", "--onlyvisible", "--pid", str(self.wallet_pid), "--name", ".*"],
                                        env=self.env, check=False, timeout=10)
        return set(result.stdout.split())

    def interact(self, display, window, container, tor, image_ids, image_platforms):
        self.env["DISPLAY"] = display
        server = self.command(["xdpyinfo", "-display", display])
        require("XTEST" in server, "XQuartz XTEST extension required for real keyboard interaction")
        xquartz = json.loads((self.evidence / "xquartz.json").read_text())
        xquartz.update(host_display=display, container_display="host.docker.internal:0",
                       xdpyinfo=server, live_process=native.xquartz_process_name(),
                       actual_XTEST_extension=True)
        require(xquartz["live_process"] is not None, "real XQuartz process disappeared")
        self.write("xquartz.json", xquartz)
        images = {}
        architectures = {"host": "darwin/arm64"}
        for service, cid in (("electron-cash", container), ("tor-proxy", tor)):
            metadata = json.loads(self.command(["docker", "inspect", cid]))[0]
            if service == "electron-cash":
                mounts = [m for m in metadata["Mounts"] if m["Destination"] == "/home/electroncash/.Xauthority"]
                require(len(mounts) == 1 and not mounts[0]["RW"], "production XQuartz cookie mount not proven")
                self.authority_path = Path(mounts[0]["Source"])
            image = json.loads(self.command(["docker", "image", "inspect", metadata["Image"]]))[0]
            actual = require_platform(service, image, image_platforms[service])
            require(image["Id"] == image_ids[service], "running image differs from built candidate")
            uname = self.command(["docker", "exec", cid, "uname", "-m"])
            require(uname == ("x86_64" if service == "electron-cash" else "aarch64"),
                    f"wrong runtime architecture: {service}: {uname}")
            images[service] = {"image_id": image["Id"], "platform": actual,
                "requested_platform": image_platforms[service], "container_id": metadata["Id"],
                "runtime_uname": uname, "build_inputs": self.inputs[service]}
            architectures["wallet" if service == "electron-cash" else "tor"] = actual
        self.write("images.json", images)
        self.write("architecture.json", architectures)
        native.tor_sock_check(container)
        self.write("tor.json", {"status": "PASS", "endpoint": "tor-proxy:9050",
            "health": self.command(["docker", "inspect", "--format", "{{.State.Health.Status}}", tor]),
            "wallet_socks5_handshake": "0500", "platform": images["tor-proxy"]["platform"]})
        observation = self.window_info(window)
        process = self.command(["docker", "exec", container, "sh", "-c",
            f"tr '\\0' ' ' </proc/{observation['pid']}/cmdline; printf '\\n'; cat /proc/{observation['pid']}/status"])
        require("electroncash-wrapper.py" in process and re.search(r"Uid:\s+10001\s+10001", process),
                "XQuartz window PID does not match the non-root wallet process")
        require(re.search(r"CapEff:\s+0+\s", process), "wallet process retained startup capabilities")
        observation.update(container_id=container, process_identity="electroncash-wrapper.py UID 10001", status="PASS")
        self.write("window.json", observation)
        self.wallet_pid = observation["pid"]
        notices = []
        for candidate in self.visible():
            title = self.command(["xdotool", "getwindowname", candidate], check=False)
            if title == "Automatic High DPI":
                self.command(["xdotool", "windowfocus", "--sync", candidate])
                self.command(["xdotool", "key", "--window", candidate, "Return"])
                deadline = time.monotonic() + 10
                while candidate in self.visible() and time.monotonic() < deadline:
                    time.sleep(.2)
                require(candidate not in self.visible(), "startup High DPI notice did not dismiss")
                notices.append(title)
        frame_name = "first-window.xwd" if self.phase == 1 else "second-window.xwd"
        observation["frame"] = native.capture_window(display, window, self.env, self.evidence / frame_name)
        observation["frame_file"] = frame_name
        self.write("window.json", observation)
        baseline = self.visible()
        self.command(["xdotool", "windowfocus", "--sync", window])
        time.sleep(2)
        self.command(["xdotool", "key", "--clearmodifiers", "alt+f"])
        time.sleep(.5)
        if not (self.visible() - baseline):
            self.command(["xdotool", "mousemove", "--window", window, "25", "12"])
            self.command(["xdotool", "click", "1"])
        deadline = time.monotonic() + 15
        popup = set()
        while time.monotonic() < deadline:
            popup = self.visible() - baseline
            if popup:
                break
            time.sleep(.2)
        self.write("interaction-attempt.json", {"tree": self.command(["xwininfo", "-root", "-tree"]),
            "baseline": sorted(baseline), "popup": sorted(popup)})
        require(popup, "real File-menu input did not map a Qt popup")
        popup_properties = [self.command(["xprop", "-id", w, "_NET_WM_WINDOW_TYPE", "_NET_WM_PID"]) for w in popup]
        require(any("_NET_WM_WINDOW_TYPE_POPUP_MENU" in p and f"= {self.wallet_pid}" in p
                    for p in popup_properties), "Qt response is not a wallet-process popup menu")
        popup_info = [self.command(["xwininfo", "-id", w]) for w in sorted(popup)]
        self.command(["xdotool", "key", "Escape"])
        time.sleep(.5)
        require(not (self.visible() & popup), "Qt File-menu popup did not dismiss")
        self.write("interaction.json", {"status": "PASS", "method": "XTEST File menu (Alt+F or pointer click) / Escape",
            "popup_ids": sorted(popup), "popup_geometry": popup_info, "popup_properties": popup_properties,
            "dismissed_startup_notices": notices})
        self.command(["xdotool", "windowfocus", "--sync", window])
        self.command(["xdotool", "key", "--window", window, "--clearmodifiers", "ctrl+q"])
        deadline = time.monotonic() + 60
        state = {}
        while time.monotonic() < deadline:
            state = json.loads(self.command(["docker", "inspect", container]))[0]["State"]
            if state["Status"] == "exited":
                break
            time.sleep(.5)
        require(state["Status"] == "exited" and state["ExitCode"] == 0 and not state["OOMKilled"],
                "Electron Cash did not quit normally with exit zero")
        result = native.command_result(["xwininfo", "-id", window], env=self.env, check=False)
        require(result.returncode != 0, "wallet window remains after Quit")
        logs = self.command(["docker", "logs", container])
        metadata = json.loads(self.command(["docker", "inspect", container]))[0]
        require(metadata["RestartCount"] == 0, "wallet restarted unexpectedly")
        require(not re.search(r"Traceback \(most recent call last\)|Segmentation fault|Fatal Python error", logs),
                "wallet crash/traceback detected")
        self.write("exit.json", {"status": "PASS", "action": "Ctrl+Q", "state": state,
            "window_disappeared": True, "crash_detected": False, "restart_count": metadata["RestartCount"]})
        self.outcomes["gui"] = "PASS"
        if self.phase == 1:
            for name in ("window.json", "interaction.json", "exit.json"):
                shutil.copyfile(self.evidence / name, self.evidence / ("first-" + name))
            require(self.restart_control is not None, "bounded restart coordination missing")
            assert self.restart_control is not None
            self.restart_control.write_text("restart\n")
            deadline = time.monotonic() + 120
            while time.monotonic() < deadline:
                state = json.loads(self.command(["docker", "inspect", container]))[0]["State"]
                if state["Status"] == "running":
                    break
                time.sleep(.5)
            require(state["Status"] == "running", "bounded Compose restart did not start")
            new_window = native.wait_window(display, 120, env=self.env)
            marker = self.command(["docker", "exec", "--user", "10001:10001", container,
                "cat", "/home/electroncash/.electron-cash/chipnet/.platform-real-persistence"])
            require(marker == "retained", "persistence marker missing on actual restart")
            self.phase = 2
            self.interact(display, new_window, container, tor, image_ids, image_platforms)
            self.outcomes["restart"] = "PASS"
            self.write("restart.json", {"status": "PASS", "launches": 2, "normal_quits": 2,
                "persisted_marker": "retained", "same_wallet_container": container,
                "second_mapped_window": new_window, "second_real_interaction": "PASS",
                "route": "mac-gui.sh production Compose up --no-build --no-deps electron-cash"})

    def cleanup(self, cleanup, before, error):
        after = {"running": native.xquartz_process_name() is not None,
            "enable_test_extensions": self.command(["defaults", "read", "org.xquartz.X11", "enable_test_extensions"], check=False) or "unset",
            "nolisten_tcp": native.command_result(["defaults", "read", "org.xquartz.X11", "nolisten_tcp"],
                                                   check=False).stdout.strip() or "unset",
            "access_sha256": native.xhost_access_fingerprint()}
        restored = (after["running"] == before["xquartz_running_before"] and
                    after["enable_test_extensions"] == before["enable_test_extensions_before"] and
                    after["nolisten_tcp"] == before["nolisten_tcp_before"] and
                    after["access_sha256"] == before["xhost_access_sha256_before"])
        cleanup.update(xquartz_restored=restored, xquartz_after=after)
        cleanup["temporary_xauthority_removed"] = self.authority_path is None or not self.authority_path.exists()
        if not cleanup["temporary_xauthority_removed"]:
            cleanup["status"] = "FAIL"
        if not restored:
            cleanup["status"] = "FAIL"
        self.write("cleanup.json", cleanup)
        if error or self.outcomes.get("restart") != "PASS":
            self.write("restart.json", {"status": "FAIL", "error": error or "restart not observed"})


def verify(directory):
    manifest = json.loads((directory / "manifest.json").read_bytes())
    required = {"result.json", "host.json", "docker.json", "xquartz.json", "candidate.json", "images.json",
                "architecture.json", "tor.json", "window.json", "interaction.json", "exit.json", "restart.json",
                "cleanup.json", "command.log", "product-inputs.json",
                "first-window.json", "first-interaction.json", "first-exit.json", "first-window.xwd", "second-window.xwd"}
    require(required <= set(manifest["files"]), "manifest omits required runtime proof")
    digest = ci.sha256_file(directory / "manifest.json")
    require(digest == (directory / "manifest.sha256").read_text().split()[0], "manifest hash mismatch")
    for name, expected in manifest["files"].items():
        require(Path(name).name == name and ci.sha256_file(directory / name) == expected,
                f"artifact hash mismatch: {name}")
    read = lambda name: json.loads((directory / name).read_bytes())
    require(read("result.json")["status"] == "PASS", "saved result is not PASS")
    host = read("host.json")
    require_host(host["system"], host["architecture"])
    candidate = read("candidate.json")
    with tempfile.TemporaryDirectory(prefix="ecd-mac-verify-") as temp:
        require(ci.candidate_identity(Path(temp))["source_fingerprint"] == candidate["source_fingerprint"],
                "current source differs from tested source")
    require(configuration() == candidate["configuration_fingerprint"], "configuration differs from tested candidate")
    require(read("architecture.json") == {"host": "darwin/arm64", "wallet": "linux/amd64", "tor": "linux/arm64"},
            "saved architecture combination invalid")
    images = read("images.json")
    require(set(images) == {"electron-cash", "tor-proxy"}, "missing actual image/platform proof")
    for service, image in images.items():
        metadata = json.loads(native.checked(["docker", "image", "inspect", image["image_id"]]))[0]
        expected = "linux/amd64" if service == "electron-cash" else "linux/arm64"
        require_platform(service, metadata, expected)
        require(image["platform"] == expected and image["requested_platform"] == expected,
                "requested/effective platform mismatch")
        require(metadata["Id"] == image["image_id"], "saved image ID invalid")
        descriptor = image["build_inputs"]
        for name, record in descriptor["inputs"].items():
            path = ROOT / name if service == "electron-cash" else ROOT / "docker/tor" / name
            require(path.is_file() and ci.sha256_file(path) == record["sha256"], f"product input changed: {path}")
            require(format(path.stat().st_mode & 0o777, "04o") == descriptor["input_modes"][name],
                    f"product input mode changed: {path}")
    for name in ("tor.json", "window.json", "interaction.json", "exit.json", "restart.json", "cleanup.json"):
        require(read(name)["status"] == "PASS", f"saved outcome failed: {name}")
    cleanup = read("cleanup.json")
    require(cleanup["xquartz_restored"] and cleanup["temporary_xauthority_removed"] and
            cleanup["temporary_runtime_removed"], "XQuartz/runtime restoration failed")
    for command in (["docker", "ps", "-aq"], ["docker", "network", "ls", "-q"]):
        for label in (f"com.docker.compose.project={cleanup['scope']}",
                      f"com.bchforge.electron-cash-docker.test-owner={cleanup['owner_token']}"):
            require(not native.checked([*command, "--filter", f"label={label}"]), "owned runtime remains")
    for claim in cleanup["claims"]:
        if claim["kind"] == "volume":
            result = native.command_result(["docker", "volume", "inspect", claim["name"]], check=False)
            require(result.returncode != 0 and "no such volume" in result.stderr.lower(),
                    "claimed disposable volume remains or cleanup cannot be verified")
    require(read("restart.json")["launches"] == 2 and read("restart.json")["normal_quits"] == 2,
            "two real launches/quits not proven")
    for name in ("first-window.json", "first-interaction.json", "first-exit.json"):
        require(read(name)["status"] == "PASS", "first launch outcome failed")
    for name in ("first-window.xwd", "second-window.xwd"):
        raw = (directory / name).read_bytes()
        header = native.unpack_xwd_header(raw)
        pixels = raw[header[0] + header[19] * 12:]
        require(header[4] > 100 and header[5] > 100 and len(set(pixels)) > 1,
                "saved Qt framebuffer is blank or unusable")
    return {"status": "PASS", "manifest_sha256": digest, "independent_process": True,
            "files_verified": len(manifest["files"]), "source_fingerprint": candidate["source_fingerprint"],
            "configuration_fingerprint": candidate["configuration_fingerprint"],
            "actual_images": {service: image["image_id"] for service, image in images.items()},
            "architecture": read("architecture.json"), "cleanup_restoration_verified": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        ci.json_write(args.verify / "verification-result.json", verify(args.verify))
        return 0
    os.environ["PATH"] = "/opt/X11/bin:/opt/homebrew/bin:" + os.environ.get("PATH", "")
    evidence = STATE / ("v1.0-mac-apple-silicon-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8])
    evidence.mkdir(parents=True, mode=0o700)
    print(f"Evidence: {evidence}", flush=True)
    validation = Validation(evidence)
    error = None
    try:
        validation.preflight()
        os.environ["ECD_MAC_ENV_FILE"] = str(ROOT / ".env.example")
        os.environ["ECD_X11_AUTOMATION"] = "1"
        require(native.run_platform("mac-xquartz", 300, validation) == 0, "production Mac runner failed")
        require_gui(validation.outcomes)
        cleanup = json.loads((evidence / "cleanup.json").read_text())
        cleanup["temporary_runtime_removed"] = (validation.restart_control is not None and
                                                not validation.restart_control.parent.exists())
        validation.write("cleanup.json", cleanup)
        require(cleanup["temporary_runtime_removed"], "task temporary runtime directory remains")
    except Exception as exc:
        error = str(exc)
    validation.write("result.json", {"status": "FAIL" if error else "PASS", "error": error,
        "command": "./scripts/ci.sh mac-apple-silicon"})
    manifest = {"schema_version": 1, "files": {p.name: ci.sha256_file(p) for p in sorted(evidence.iterdir()) if p.is_file()}}
    validation.write("manifest.json", manifest)
    (evidence / "manifest.sha256").write_text(ci.sha256_file(evidence / "manifest.json") + "  manifest.json\n")
    if not error:
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--verify", str(evidence)])
        if result.returncode:
            error = "independent evidence verification failed"
    if error:
        print(f"RESULT: FAIL: {error}", file=sys.stderr)
        return 1
    print("RESULT: PASS", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
