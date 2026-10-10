#!/usr/bin/env python3
"""Opt-in real local X11 acceptance, independent of the headless gate.

Use the supported platform_runner Compose route and private x11-authority
service. No forwarding, Xvfb, offscreen Qt, browser, or operator steps.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import platform_runner as native  # pyright: ignore[reportMissingImports]
import ci  # pyright: ignore[reportMissingImports]

STATE = Path.home() / ".local/state/electron-cash-docker"


def require(condition, message):
    if not condition:
        raise native.RunnerError(message)


def server_identity(display, pid, executable, arguments):
    require(bool(re.fullmatch(r":\d+(?:\.\d+)?", display)), "only a local Unix DISPLAY qualifies")
    name = Path(executable).name
    require(name in ("Xorg", "Xwayland"), f"non-qualifying server {name!r}; Xvfb/synthetic servers rejected")
    require("-ac" not in arguments, "X server disables access control")
    require(not any(arguments[i:i+2] == ["-listen", "tcp"] for i in range(len(arguments))),
            "X server explicitly listens on TCP")
    return {"pid": int(pid), "executable": executable, "server": name,
            "display": display, "synthetic_xvfb": False}


def local_servers():
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = (entry / "cmdline").read_bytes().decode().split("\0")[:-1]
            if not args or Path(args[0]).name not in ("Xorg", "Xwayland", "Xvfb"):
                continue
            display = next((arg for arg in args if re.fullmatch(r":\d+(?:\.\d+)?", arg)), None)
            if display:
                executable = subprocess.run(["readlink", str(entry / "exe")], capture_output=True,
                                            text=True, timeout=5)
                if executable.returncode:
                    executable = subprocess.run(["sudo", "-n", "readlink", str(entry / "exe")],
                                                capture_output=True, text=True, timeout=5)
                if executable.returncode == 0:
                    found.append((display, entry.name, executable.stdout.strip(), args))
        except (OSError, UnicodeError):
            continue
    return found


def drm_blockers():
    """Capture only blocked DRM/QXL kernel stacks, not unrelated host processes."""
    code = '''from pathlib import Path
import json
records=[]
for p in Path('/proc').iterdir():
 if not p.name.isdigit(): continue
 try:
  lines=(p/'status').read_text().splitlines()
  state=next(x for x in lines if x.startswith('State:'))
  if 'D (' not in state: continue
  stack=(p/'stack').read_text()
  if not any(s in stack for s in ('qxl_', 'drm_modeset_lock')): continue
  records.append({'pid':int(p.name),'name':(p/'comm').read_text().strip(),
    'state':state,'stack':stack,'pending_signals':[x for x in lines if x.startswith(('SigPnd:', 'ShdPnd:'))]})
 except OSError: pass
print(json.dumps(records))'''
    result = subprocess.run(["sudo", "-n", "python3", "-c", code], capture_output=True, text=True, timeout=10)
    return json.loads(result.stdout) if result.returncode == 0 else []


def choose_display():
    for number in range(90, 300):
        if not Path(f"/tmp/.X11-unix/X{number}").exists() and not Path(f"/tmp/.X{number}-lock").exists():
            return f":{number}"
    raise native.PrerequisiteError("no free local Xorg display number")


class Validation:
    def __init__(self, evidence):
        self.evidence = evidence
        self.project = "ecd-linux-x11-test-" + uuid.uuid4().hex
        self.phase = "A"
        self.env = {"PATH": os.environ.get("PATH", ""), "HOME": str(Path.home()),
                    **native.dotenv(ROOT / ".env.example")}
        self.env.update(COMPOSE_PROJECT_NAME=self.project, ECD_WALLET_VOLUME=self.project + "-wallet",
                        ECD_TOR_VOLUME=self.project + "-tor", NETWORK="chipnet", USE_TOR="true",
                        CASHFUSION_ENABLED="true", CASHFUSION_AUTO_FUSE="false",
                        WALLET_AUTO_CREATE="true", TEST_WALLET_PASSWORD="",
                        BASIC_AUTH_PASSWORD=secrets.token_hex(24), JSONRPC_ENABLED="false",
                        ELECTRONCASH_ARGS="", EC_LANGUAGE="en_US", DARK_MODE="false")
        self.temp: Any = None
        self.xorg: Any = None
        self.xorg_pid: Any = None
        self.compose: Any = None
        self.xserver: Any = None
        self.started = False
        self.outcomes = {}

    def write(self, name, value):
        ci.json_write(self.evidence / name, value)

    def command(self, args, *, timeout=90, check=True):
        result = native.command_result(args, env=self.env, timeout=timeout, check=False)
        # Log commands/status only, never environment, xauth records or wallet content.
        if args[0] != "xauth":
            with (self.evidence / "command.log").open("a") as log:
                log.write(json.dumps({"phase": self.phase, "command": args, "returncode": result.returncode}) + "\n")
        if check:
            require(result.returncode == 0, f"{args[0]} failed ({result.returncode}): {result.stderr[-1800:]}")
        return result.stdout.strip()

    def resolve_images(self):
        base = ["docker", "compose", "--env-file", str(ROOT / ".env.example"), "-f", str(ROOT / "docker-compose.yml")]
        model = json.loads(self.command([*base, "config", "--format", "json"]))
        paths = ([Path(os.environ["ECD_X11_IMAGE_PROOF"])] if os.environ.get("ECD_X11_IMAGE_PROOF") else
                 sorted([*STATE.glob("**/focused-images*.json"), *STATE.glob("**/image-proof.json")],
                        key=lambda p: p.stat().st_mtime, reverse=True))
        proofs = []
        for path in paths:
            try:
                proofs.append((path, json.loads(path.read_text())["proof"]))
            except (OSError, ValueError, KeyError):
                continue
        selected = {}
        for service, variant, variable in (("electron-cash", "electron-cash-normal", "ELECTRON_CASH_IMAGE"),
                                            ("tor-proxy", "tor-proxy", "TOR_IMAGE")):
            descriptor = ci.image_build_configuration(model, service, model["services"][service]["image"],
                variant=variant, compose_files=[ROOT / "docker-compose.yml"])
            for path, records in proofs:
                proof = records.get(service, {})
                try:
                    ci.validate_image_reuse(descriptor, proof)
                    image = json.loads(self.command(["docker", "image", "inspect", proof["image_id"]]))[0]
                    require(image["Os"] == "linux" and image["Architecture"] == "amd64", "image platform mismatch")
                except (ci.ValidationError, native.RunnerError, KeyError):
                    continue
                selected[service] = {**descriptor, "image_id": image["Id"], "proof_path": str(path),
                    "proof_sha256": ci.sha256_file(path), "status": "PASS", "input_modes": proof["input_modes"]}
                break
            if service not in selected:
                tag = "ecd-linux-x11-" + service + ":" + descriptor["configuration_sha256"][:32]
                self.env[variable] = tag
                self.command([*base, "build", service], timeout=1800)
                image_id = self.command(["docker", "image", "inspect", "--format", "{{.Id}}", tag])
                selected[service] = {**descriptor, "status": "PASS", "image_id": image_id,
                    "input_modes": {p: format((Path(descriptor["context"]) / p).stat().st_mode & 0o777, "04o")
                                    for p in descriptor["inputs"]}}
            self.env[variable] = selected[service]["image_id"]
        self.write("image-proof.json", {"proof": selected})
        return selected

    def configuration_fingerprint(self):
        return ci.sha256_bytes(json.dumps({n: ci.sha256_file(ROOT / n) for n in
            (".env.example", "docker-compose.yml", "docker-compose.gui.yml", "docker-compose.headless.yml",
             "docker-compose.hw.yml", "docker-compose.rpc.yml")},
            sort_keys=True, separators=(",", ":")).encode())

    def preflight(self):
        require(platform.system() == "Linux", "Linux host required")
        native.require_tools("docker", "xdpyinfo", "xwininfo", "xprop", "xwd", "xauth", "xdotool")
        endpoint = json.loads(self.command(["docker", "context", "inspect", "default", "--format", "{{json .Endpoints.docker}}"] ))
        require(endpoint.get("Host", "").startswith("unix://"), "local Docker Engine required")
        version = self.command(["docker", "version", "--format", "{{.Server.Version}}"])
        cards = sorted(Path("/dev/dri").glob("card*"))
        connectors = {p.name: (p / "status").read_text().strip() for p in Path("/sys/class/drm").glob("card*-*")
                      if (p / "status").exists()}
        self.write("host.json", {"hostname": platform.node(), "system": platform.system(),
            "architecture": platform.machine(), "docker": version, "drm_cards": [str(p) for p in cards],
            "connectors": connectors, "initial_xservers": [s[0] for s in local_servers()],
            "prerequisites": self.command(["dpkg-query", "-W", "xserver-xorg-core", "xserver-xorg-video-dummy",
                                            "x11-utils", "xauth", "xdotool"], check=False)})
        self.candidate = ci.candidate_identity(self.evidence)
        self.images = self.resolve_images()
        self.candidate["images"] = {k: v["image_id"] for k, v in self.images.items()}
        self.candidate["configuration_fingerprint"] = self.configuration_fingerprint()
        self.write("candidate.json", self.candidate)

    def display_setup(self):
        self.phase = "B"
        blockers = drm_blockers()
        if blockers:
            self.write("host-blocker.json", {"classification": "HOST_X11_FAILURE",
                "observation": blockers, "disposition": "DRM skipped; independent Xorg/dummy fallback permitted",
                "driver": (Path("/sys/class/drm/card0/device/uevent").read_text()
                           if Path("/sys/class/drm/card0/device/uevent").exists() else "unknown"),
                "pci_reset_available": Path("/sys/class/drm/card0/device/reset").exists(),
                "reason": "host DRM kernel paths in uninterruptible D state; do not retry QXL"})
        requested = os.environ.get("DISPLAY", "")
        servers = local_servers()
        info: Any = None
        if requested:
            match = next((s for s in servers if s[0].split(".")[0] == requested.split(".")[0]), None)
            if match is None:
                raise native.PrerequisiteError("HOST_X11_FAILURE: DISPLAY has no identifiable local X server")
            info = server_identity(*match)
            self.env.update(DISPLAY=requested, XAUTHORITY=os.environ.get("XAUTHORITY", str(Path.home() / ".Xauthority")))
            self.command(["xdpyinfo", "-display", requested], timeout=10)
        else:
            for server in servers:
                if Path(server[2]).name not in ("Xorg", "Xwayland"):
                    continue
                if any(int(server[1]) == record["pid"] for record in blockers):
                    continue
                args = server[3]
                authority = args[args.index("-auth") + 1] if "-auth" in args else str(Path.home() / ".Xauthority")
                if not os.access(authority, os.R_OK):
                    continue
                self.env.update(DISPLAY=server[0], XAUTHORITY=authority)
                try:
                    accessible = native.run(["xdpyinfo", "-display", server[0]], env=self.env, timeout=5).returncode == 0
                except subprocess.TimeoutExpired:
                    accessible = False
                if accessible:
                    info = server_identity(*server)
                    break
            if info is None:
                cards = sorted(Path("/dev/dri").glob("card*"))
                if cards and not blockers:
                    try:
                        info = self.start_xorg("modesetting", cards[0])
                    except native.RunnerError as error:
                        self.write("drm-attempt.json", {"status": "FAIL", "error": str(error)})
                        self.stop_owned_xorg()
                if info is None:
                    info = self.start_xorg("dummy")
        details = self.command(["xdpyinfo", "-display", self.env["DISPLAY"]], timeout=10)
        info["xdpyinfo"] = "\n".join(line.strip() for line in details.splitlines() if any(key in line
            for key in ("vendor", "version number", "dimensions:", "depth of root", "number of screens")))
        info["task_owned"] = bool(self.xorg)
        info["xdpyinfo_success"] = True
        if blockers and info.get("driver") == "dummy":
            previous = []
            for directory in STATE.glob("v*-linux-x11-*"):
                if directory == self.evidence:
                    continue
                try:
                    result = json.loads((directory / "result.json").read_text())
                    server = json.loads((directory / "xserver.json").read_text())
                    if result.get("classification") == "HOST_X11_FAILURE" and server.get("driver") == "qxl":
                        previous.append({"evidence": str(directory), "manifest_sha256": ci.sha256_file(directory / "manifest.json"),
                                         "status": "superseded failed QXL/DRM backend attempt"})
                except (OSError, ValueError):
                    continue
            self.write("supersedes.json", {"previous_backend_attempts": previous,
                "accepted_backend": "genuine Xorg/dummy; real native Linux X11; no GPU/DRM claim"})
        self.xserver = info
        self.write("xserver.json", info)

    def start_xorg(self, driver, card=None):
        native.require_tools("Xorg", "sudo")
        self.command(["sudo", "-n", "true"])
        display = choose_display()
        authority = self.temp / "authority"
        merged = subprocess.run(["xauth", "-f", str(authority)],
            input=f"add {display} MIT-MAGIC-COOKIE-1 {secrets.token_hex(16)}\n",
            text=True, capture_output=True, timeout=10)
        require(merged.returncode == 0, "cannot create task-owned Xauthority")
        authority.chmod(0o600)
        config = self.temp / "xorg.conf"
        flags = ('Section "ServerFlags"\n Option "AutoAddDevices" "false"\n'
                 ' Option "AutoAddGPU" "false"\n Option "AutoBindGPU" "false"\nEndSection\n')
        if driver == "dummy":
            config.write_text(flags + 'Section "Device"\n Identifier "ECD-Dummy"\n Driver "dummy"\n'
                ' VideoRam 32768\nEndSection\nSection "Monitor"\n Identifier "ECD-Monitor"\n'
                ' HorizSync 30-90\n VertRefresh 50-75\n'
                ' Modeline "1280x800" 83.50 1280 1352 1480 1680 800 803 809 831 -HSync +VSync\n'
                'EndSection\nSection "Screen"\n Identifier "ECD-Screen"\n Device "ECD-Dummy"\n'
                ' Monitor "ECD-Monitor"\n DefaultDepth 24\n SubSection "Display"\n'
                ' Depth 24\n Modes "1280x800"\n EndSubSection\nEndSection\n')
        else:
            config.write_text(flags + 'Section "Device"\n Identifier "ECD-KMS"\n Driver "modesetting"\n'
                f' Option "kmsdev" "{card}"\n Option "AccelMethod" "none"\nEndSection\n'
                'Section "Screen"\n Identifier "ECD-Screen"\n Device "ECD-KMS"\n DefaultDepth 24\nEndSection\n')
        command = ["sudo", "-n", shutil.which("Xorg"), display, "-config", str(config),
            "-logfile", str(self.temp / "Xorg.log"), "-auth", str(authority),
            "-nolisten", "tcp", "-noreset", "-novtswitch", "-sharevts"]
        if driver == "dummy":
            # A separate seat excludes seat0's QXL platform device from Xorg probing.
            # This is genuine Xorg/dummy, not a nested server or framebuffer substitute.
            command += ["-seat", self.project + "-dummy"]
        self.xorg = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.env.update(DISPLAY=display, XAUTHORITY=str(authority))
        self.xorg_pid = None
        info = None
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            match = next((s for s in local_servers() if s[0] == display and str(config) in s[3]), None)
            if match:
                self.xorg_pid = int(match[1])
                try:
                    reachable = native.run(["xdpyinfo", "-display", display], env=self.env, timeout=5).returncode == 0
                except subprocess.TimeoutExpired:
                    reachable = False
                if reachable:
                    info = server_identity(*match)
                    break
            if self.xorg.poll() is not None:
                break
            time.sleep(0.5)
        log_path = self.temp / "Xorg.log"
        log = log_path.read_text(errors="replace") if log_path.exists() else "no Xorg log"
        self.write(f"xorg-{driver}-diagnostic.json", {"log": log, "command": command})
        if info is None:
            raise native.PrerequisiteError(f"HOST_X11_FAILURE: Xorg/{driver} failed: " + log[-2200:])
        require(("DUMMY(0)" if driver == "dummy" else "modeset(0)") in log, "Xorg loaded video driver not proven")
        info.update(backend="headless Xorg/dummy" if driver == "dummy" else "DRM/KMS",
                    driver=driver, drm_dependency=driver != "dummy",
                    version=next((line.strip() for line in log.splitlines() if "X.Org X Server" in line), "unknown"))
        if driver == "dummy":
            require("Adding drm device" not in log, "dummy Xorg unexpectedly probed DRM")
        else:
            require(str(card) in log, "DRM device not proven")
            info["drm_device"] = str(card)
        return info

    def stop_owned_xorg(self):
        if self.xorg is None:
            return
        if self.xorg_pid and Path(f"/proc/{self.xorg_pid}").exists():
            self.command(["sudo", "-n", "kill", "-TERM", str(self.xorg_pid)])
        try:
            self.xorg.wait(timeout=10)
        except subprocess.TimeoutExpired:
            raise native.RunnerError("new DRM attempt could not exit; independent fallback cannot reuse its process")
        self.xorg = self.xorg_pid = None

    def launch(self):
        self.phase = "C"
        self.compose = native.compose_args("linux-x11", self.project, ROOT / ".env.example")
        model = json.loads(self.command([*self.compose, "config", "--format", "json"]))
        wallet = model["services"]["electron-cash"]
        require(wallet["environment"]["MODE"] == "gui" and wallet["environment"]["ECD_GUI_SESSION"] == "false",
                "supported native GUI mode not selected")
        require(not wallet.get("ports") and not wallet.get("expose"), "native GUI publishes unexpected services")
        require(all(v.get("name", "").startswith(self.project) for v in model["volumes"].values()),
                "non-task-owned volume in resolved configuration")
        self.started = True
        self.command([*self.compose, "up", "-d", "--no-build", "electron-cash"], timeout=180)
        self.container = native.container_for(self.project)
        require(self.container, "native wallet container absent")
        item = json.loads(self.command(["docker", "inspect", self.container]))[0]
        require(item["Image"] == self.images["electron-cash"]["image_id"], "running wallet image mismatch")
        require(not any(item["NetworkSettings"]["Ports"].values()), "unexpected published container port")
        self.write("launch.json", {"status": "PASS", "runner": "platform_runner.compose_args",
            "compose_files": ["docker-compose.yml", "docker-compose.gui.yml"], "project": self.project,
            "container": self.container, "image_id": item["Image"], "mode": "gui",
            "xauthority_service": "x11-authority", "published_ports": []})
        self.outcomes["Native ECD launch"] = "PASS"

    def frame(self, window):
        raw = subprocess.run(["xwd", "-id", window, "-silent"], env=self.env, capture_output=True, timeout=10)
        require(raw.returncode == 0, "cannot read real Qt X11 framebuffer")
        header = native.unpack_xwd_header(raw.stdout)
        pixels = raw.stdout[header[0] + header[19] * 12:]
        require(header[4] > 100 and header[5] > 100 and len(set(pixels)) > 1, "blank/unusable Qt window")
        return hashlib.sha256(pixels).hexdigest()

    def window_interaction_exit(self):
        self.phase = "D"
        window = native.wait_window(self.env["DISPLAY"], 120, env=self.env)
        details = self.command(["xwininfo", "-id", window])
        props = self.command(["xprop", "-id", window, "WM_CLASS", "WM_NAME", "_NET_WM_PID"])
        require("IsViewable" in details and "electron" in props.lower(), "mapped Electron Cash Qt window not proven")
        top = self.command(["docker", "top", self.container, "-eo", "uid,pid,args"])
        require(not re.search(r"Xvfb|websockify|x11vnc", top), "synthetic/browser runtime detected")
        identity: Any = native.wallet_process_identity(top)
        if identity is None or identity[0] != "10001":
            raise native.RunnerError("non-root Electron Cash process missing")
        container_pid = self.command(["docker", "exec", self.container, "pgrep", "-f", "electroncash-wrapper.py"])
        pid_match = re.search(r"_NET_WM_PID\(CARDINAL\) = (\d+)", props)
        if pid_match is None or pid_match[1] not in container_pid.split():
            raise native.RunnerError("window PID does not match wallet Qt process")
        self.write("window.json", {"status": "PASS", "window_id": window, "properties": props, "geometry": details,
            "wallet_host_pid": identity[1], "wallet_container_pid": pid_match[1], "container": self.container,
            "qt_platform": "xcb (real mapped X11 window)"})
        self.outcomes["Electron Cash window"] = "PASS"
        self.phase = "E"
        notices = []
        for candidate in self.mapped_qt_windows(pid_match[1]):
            title = self.command(["xdotool", "getwindowname", candidate], check=False)
            if title == "Automatic High DPI":
                self.command(["xdotool", "windowfocus", "--sync", candidate])
                self.command(["xdotool", "key", "Return"])
                time.sleep(0.5)
                require(candidate not in self.mapped_qt_windows(pid_match[1]), "startup High DPI notice did not close")
                notices.append({"title": title, "action": "Return", "dismissed": True})
        self.command(["xdotool", "windowfocus", "--sync", window])
        time.sleep(2)
        before = self.frame(window)
        previous_windows = self.mapped_qt_windows(pid_match[1])
        self.command(["xdotool", "key", "alt+f"])
        time.sleep(1)
        tree = self.command(["xwininfo", "-root", "-tree"])
        after = self.frame(window)
        popups = self.mapped_qt_windows(pid_match[1]) - previous_windows
        self.write("interaction-attempt.json", {"before_windows": sorted(previous_windows), "popup_ids": sorted(popups),
            "tree": tree, "before_frame": before, "after_frame": after,
            "properties": {w: self.command(["xprop", "-id", w, "WM_CLASS", "_NET_WM_PID", "_NET_WM_WINDOW_TYPE",
                                           "WM_TRANSIENT_FOR", "WM_CLIENT_LEADER"], check=False)
                           for w in re.findall(r'^\s*(0x[0-9a-fA-F]+)', tree, re.MULTILINE)}})
        require(bool(popups), "GUI did not map a real File-menu popup in response to X11 input")
        popup_types = {w: self.command(["xprop", "-id", w, "_NET_WM_WINDOW_TYPE"]) for w in popups}
        require(any("_NET_WM_WINDOW_TYPE_POPUP_MENU" in value for value in popup_types.values()),
                "mapped Qt response is not an X11 popup menu")
        self.command(["xdotool", "key", "Escape"])
        time.sleep(0.5)
        require(not (popups & self.mapped_qt_windows(pid_match[1])), "Escape did not dismiss Qt menu")
        self.write("interaction.json", {"status": "PASS", "action": "focus; Alt+F File menu; Escape",
            "input": "XTEST through xdotool", "before_frame_sha256": before, "after_frame_sha256": after,
            "window_tree": tree, "mapped_popup_ids": sorted(popups), "popup_dismissed": True,
            "startup_notices": notices, "popup_types": popup_types})
        self.outcomes["GUI interaction"] = "PASS"
        self.phase = "F"
        self.command(["xdotool", "key", "ctrl+q"])
        deadline = time.monotonic() + 60
        state = None
        item: Any = None
        while time.monotonic() < deadline:
            item = json.loads(self.command(["docker", "inspect", self.container]))[0]
            state = item["State"]
            if state["Status"] == "exited":
                break
            time.sleep(1)
        require(state and state["Status"] == "exited" and state["ExitCode"] == 0 and not state["OOMKilled"],
                f"normal Ctrl+Q Qt exit failed: {state}")
        logs = self.command(["docker", "logs", self.container])
        require(not re.search(r"Traceback \(most recent call last\)|Segmentation fault|Aborted|core dumped", logs), "Qt crash in logs")
        require(not Path("/proc", identity[1]).exists(), "wallet process remains after Qt exit")
        remaining_tree = self.command(["xwininfo", "-root", "-tree"])
        require(window not in re.findall(r'^\s*(0x[0-9a-fA-F]+)', remaining_tree, re.MULTILINE),
                "Qt top-level window remains after normal Quit")
        require(item["RestartCount"] == 0, "wallet unexpectedly restarted")
        self.write("exit.json", {"status": "PASS", "action": "native Ctrl+Q", "state": state,
            "wallet_process_absent": True, "window_absent": True, "crash_traceback": False,
            "restart_count": item["RestartCount"]})
        self.outcomes["Clean Qt exit"] = "PASS"

    def mapped_qt_windows(self, pid):
        tree = self.command(["xwininfo", "-root", "-tree"])
        mapped = set()
        for window in re.findall(r'^\s*(0x[0-9a-fA-F]+)', tree, re.MULTILINE):
            props = self.command(["xprop", "-id", window, "_NET_WM_PID", "WM_CLASS"], check=False)
            if f"_NET_WM_PID(CARDINAL) = {pid}" not in props:
                continue
            if "IsViewable" in self.command(["xwininfo", "-id", window], check=False):
                mapped.add(window)
        return mapped

    def cleanup(self):
        self.phase = "G"
        failures = []
        if self.started:
            try:
                self.command([*self.compose, "down", "--volumes", "--remove-orphans"], timeout=120)
                for kind, command in (("containers", ["docker", "ps", "-aq"]), ("volumes", ["docker", "volume", "ls", "-q"]),
                                      ("networks", ["docker", "network", "ls", "-q"])):
                    require(not self.command([*command, "--filter", f"label=com.docker.compose.project={self.project}"]),
                            f"task-owned {kind} remain")
            except Exception as error:
                failures.append(str(error))
        if self.xorg:
            try:
                log = self.temp / "Xorg.log"
                if log.exists():
                    self.write("xorg-diagnostic.json", {"log": log.read_text(errors="replace")})
                if self.xorg_pid and Path(f"/proc/{self.xorg_pid}").exists():
                    self.command(["sudo", "-n", "kill", "-TERM", str(self.xorg_pid)])
                try:
                    self.xorg.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    if self.xorg_pid:
                        self.command(["sudo", "-n", "kill", "-KILL", str(self.xorg_pid)])
                    self.xorg.wait(timeout=5)
                require(not self.xorg_pid or not Path(f"/proc/{self.xorg_pid}").exists(), "task Xorg remains")
            except Exception as error:
                failures.append(str(error))
                self.write("host-blocker.json", {"classification": "HOST_X11_FAILURE", "kernel_waits": drm_blockers()})
                # Reap the task launcher even when the kernel cannot reap its Xorg child.
                if self.xorg.poll() is None:
                    try:
                        self.command(["sudo", "-n", "kill", "-KILL", str(self.xorg.pid)])
                        self.xorg.wait(timeout=5)
                    except Exception as launcher_error:
                        failures.append(str(launcher_error))
        if self.temp:
            try:
                shutil.rmtree(self.temp)
                require(not self.temp.exists(), "temporary credentials/configuration remain")
            except Exception as error:
                failures.append(str(error))
        result = {"status": "FAIL" if failures else "PASS", "project": self.project,
                  "xorg_stopped": bool(self.xorg) and not (self.xorg_pid and Path(f"/proc/{self.xorg_pid}").exists()),
                  "existing_session_preserved": not bool(self.xorg), "temporary_files_removed": bool(self.temp),
                  "failures": failures, "scope": "only unique task-owned resources"}
        self.write("cleanup.json", result)
        self.outcomes["Cleanup"] = result["status"]
        return result

    def execute(self):
        error = failed_phase = None
        try:
            tasks = STATE / "tasks"
            tasks.mkdir(parents=True, exist_ok=True)
            # Home-backed task directory avoids per-user /tmp quotas. X socket is still local.
            self.temp = Path(tempfile.mkdtemp(prefix="ecd-linux-x11-", dir=tasks))
            self.env["TMPDIR"] = str(self.temp)
            self.preflight()
            self.display_setup()
            self.launch()
            self.window_interaction_exit()
            end = ci.candidate_identity(self.evidence)
            require(end["source_fingerprint"] == self.candidate["source_fingerprint"], "source changed during test")
            require(self.configuration_fingerprint() == self.candidate["configuration_fingerprint"], "configuration changed during test")
        except (Exception, KeyboardInterrupt) as caught:
            error, failed_phase = str(caught), self.phase
        finally:
            cleanup = self.cleanup()
        status = "PASS" if error is None and cleanup["status"] == "PASS" else "FAIL"
        classification = ("HOST_X11_FAILURE" if failed_phase == "B" else "PRODUCT_X11_FAILURE"
                          if failed_phase in ("C", "D", "E", "F") else "TEST_HARNESS_FAILURE")
        result = {"status": status, "exit_code": 0 if status == "PASS" else 1, "phase": failed_phase,
                  "classification": classification if status != "PASS" else None, "error": error,
                  "outcomes": self.outcomes, "command": "./scripts/ci.sh linux-x11"}
        self.write("result.json", result)
        for name in ("host", "xserver", "candidate", "window", "interaction"):
            if not (self.evidence / f"{name}.json").exists():
                self.write(f"{name}.json", {"status": "NOT_RUN", "failed_phase": failed_phase})
        manifest = {"schema_version": 1, "files": {p.name: ci.sha256_file(p)
                    for p in sorted(self.evidence.iterdir()) if p.is_file()}}
        self.write("manifest.json", manifest)
        digest = ci.sha256_file(self.evidence / "manifest.json")
        (self.evidence / "manifest.sha256").write_text(digest + "  manifest.json\n")
        verification = {"status": "PASS", "manifest_sha256": digest, "files_verified": len(manifest["files"]),
                        "hashes_match": all(ci.sha256_file(self.evidence / n) == h for n, h in manifest["files"].items())}
        require(verification["hashes_match"], "evidence verification failed")
        self.write("verification-result.json", verification)
        print("Linux X11 validation\n--------------------")
        print(f"Host: {platform.node()} / {platform.system()} {platform.machine()}")
        if self.xserver:
            print(f"X server: {self.xserver['server']}\nDisplay: {self.xserver['display']}\n"
                  f"Backend: {self.xserver.get('backend', 'existing local session')}\nSynthetic Xvfb: NO")
            print(f"Video driver: {self.xserver.get('driver', 'existing session')}\nxdpyinfo: PASS")
        if hasattr(self, "images"):
            print("Wallet image: " + self.images["electron-cash"]["image_id"])
        for label in ("Native ECD launch", "Electron Cash window", "GUI interaction", "Clean Qt exit", "Cleanup"):
            print(f"{label}: {self.outcomes.get(label, 'NOT_RUN')}")
        if error:
            print(f"Phase {failed_phase} / {classification}: {error}")
        print(f"Evidence: {self.evidence}\nManifest SHA-256: {digest}\nRESULT: {status}")
        return result["exit_code"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--evidence-dir", type=Path)
    args = parser.parse_args()
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    evidence = args.evidence_dir or STATE / ("v" + (ROOT / "VERSION").read_text().strip() + "-linux-x11-" + run_id)
    evidence.mkdir(parents=True, mode=0o700, exist_ok=False)
    (evidence / "command.log").touch(mode=0o600)
    def interrupted(_signal, _frame):
        raise KeyboardInterrupt("platform validation interrupted")
    signal.signal(signal.SIGTERM, interrupted)
    return Validation(evidence).execute()


if __name__ == "__main__":
    raise SystemExit(main())
