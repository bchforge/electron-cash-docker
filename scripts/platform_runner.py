#!/usr/bin/env python3
"""Simple, opt-in real-platform Electron Cash checks.

Run only on the named host. The checks use the production native GUI path,
disposable Chipnet state and task-owned Docker resources.
"""
from __future__ import annotations

import argparse
import atexit
import fcntl
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any

import docker_ownership
import ci as ci_validation
import x11_relay


ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = ROOT / ".env.example"
ENV_LOCAL = ROOT / ".env"
SCOPES = ("linux-x11", "mac-xquartz", "ledger-linux")
IMAGE_PLATFORM = "linux/amd64"


class RunnerError(RuntimeError):
    """The target environment or a required observed scenario failed."""


class PrerequisiteError(RunnerError):
    """The requested platform check could not be started."""


class OperatorActionUnavailable(RunnerError):
    """The operator did not complete an explicitly requested GUI action."""


def run(command: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 90) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
                          capture_output=True, check=False, timeout=timeout)


def checked(command: list[str], *, timeout: int = 90,
            env: dict[str, str] | None = None) -> str:
    result = run(command, timeout=timeout, env=env)
    if result.returncode:
        raise RunnerError(f"command failed ({result.returncode}): {' '.join(command)}: "
                          f"{(result.stdout + result.stderr)[-3000:]}")
    return result.stdout.strip()


def command_result(command: list[str], *, env: dict[str, str] | None = None,
                   timeout: int = 120, check: bool = True,
                   input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, encoding="utf-8", errors="replace",
                            input=input_text, capture_output=True, timeout=timeout, check=False)
    if check and result.returncode:
        raise RunnerError(f"command failed ({result.returncode}): {' '.join(command)}: "
                          f"{(result.stdout + result.stderr)[-3000:]}")
    return result


def signal_launch_group(process: subprocess.Popen, signal_number: int) -> None:
    """Signal only the isolated launcher/Compose process group owned by this run."""
    try:
        os.killpg(process.pid, signal_number)
    except ProcessLookupError:
        pass


def wallet_process_identity(process_table: str) -> tuple[str, str] | None:
    """Return (UID, host PID) for the Electron Cash wrapper in docker top output."""
    for line in process_table.splitlines()[1:]:
        columns = line.split(None, 2)
        if (len(columns) == 3 and columns[1].isdigit() and
                "electroncash-wrapper.py" in columns[2]):
            return columns[0], columns[1]
    return None


def supplementary_groups_from_status(status: str) -> set[int]:
    """Parse UID and supplementary groups from one Linux proc status record."""
    uid_line = re.search(r"^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", status, re.MULTILINE)
    groups_line = re.search(r"^Groups:\s*(.*?)\s*$", status, re.MULTILINE)
    if uid_line is None or groups_line is None or any(uid != "10001" for uid in uid_line.groups()):
        raise RunnerError("Electron Cash process identity could not be verified as non-root UID 10001")
    try:
        return {int(group) for group in groups_line.group(1).split()}
    except ValueError as error:
        raise RunnerError("Electron Cash supplementary-group data is malformed") from error


def process_supplementary_groups(pid: str) -> set[int]:
    """Read the actual kernel supplementary-group set for one host process."""
    if not pid.isdigit():
        raise RunnerError("Electron Cash host PID is malformed")
    try:
        status = (Path("/proc") / pid / "status").read_text(encoding="utf-8")
    except OSError as error:
        raise RunnerError("unable to verify Electron Cash supplementary groups") from error
    return supplementary_groups_from_status(status)


def wallet_process_uid(process_table: str) -> str | None:
    """Return the numeric UID for the Electron Cash wrapper in docker top output."""
    identity = wallet_process_identity(process_table)
    return identity[0] if identity is not None else None


def redact_host_text(value: str) -> str:
    value = value.replace(str(ROOT), "$REPO").replace(str(Path.home()), "$HOME")
    return re.sub(r"/tmp/ecd-[^/\s]+", "$TEMP", value)


def require_tools(*names: str) -> None:
    missing = [name for name in names if shutil.which(name) is None]
    if missing:
        raise PrerequisiteError("missing required host tools: " + ", ".join(missing))


def xquartz_process_name() -> str | None:
    """Return the active XQuartz process name, distinguishing unknown from stopped."""
    for name in ("X11", "X11.bin"):
        result = command_result(["pgrep", "-x", name], check=False)
        if result.returncode == 0:
            return name
        if result.returncode != 1:
            raise PrerequisiteError("unable to determine whether XQuartz is running; refusing to continue")
    return None


def xquartz_socket_display(display: str) -> str:
    """Resolve the launchd DISPLAY alias to the XQuartz server's socket display."""
    if "/org.xquartz:" in display:
        return display.rsplit("/org.xquartz", 1)[1]
    return display


def xauthority_has_mit_cookie(display: str) -> bool:
    candidates = [display]
    socket_display = xquartz_socket_display(display)
    if socket_display and socket_display not in candidates:
        candidates.append(socket_display)
    for candidate in candidates:
        listed = command_result(["xauth", "list", candidate], check=False)
        if listed.returncode != 0:
            continue
        if not any(len(fields := line.split()) >= 2 and fields[1] == "MIT-MAGIC-COOKIE-1"
                   for line in listed.stdout.splitlines()):
            continue
        records = command_result(["xauth", "nlist", candidate], check=False)
        if records.returncode == 0 and records.stdout.strip():
            return True
    return False


def xhost_access_fingerprint() -> str:
    result = command_result(["xhost"], check=False)
    if result.returncode:
        return "unavailable"
    return hashlib.sha256(result.stdout.encode()).hexdigest()


def parse_xauthority_record(line: str) -> tuple[list[str], str, str]:
    """Validate one xauth nlist record without exposing its cookie."""
    fields = line.split()
    if len(fields) != 9 or any(not re.fullmatch(r"[0-9a-fA-F]+", field) for field in fields):
        raise ValueError("xauth nlist returned a malformed record")
    if len(fields[0]) != 4:
        raise ValueError("xauth nlist returned a malformed family field")
    for length_index, value_index in ((1, 2), (3, 4), (5, 6), (7, 8)):
        if len(fields[length_index]) != 4 or len(fields[value_index]) != int(fields[length_index], 16) * 2:
            raise ValueError("xauth nlist returned an inconsistent record length")
    try:
        display_number = bytes.fromhex(fields[4]).decode("ascii")
        protocol = bytes.fromhex(fields[6]).decode("ascii")
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("xauth nlist returned invalid display or protocol metadata") from error
    if (not display_number.isdecimal() or len(display_number) > 5 or
            not protocol or not fields[8]):
        raise ValueError("xauth nlist returned empty or invalid record metadata")
    return fields, display_number, protocol


def xauthority_records_for_display(display: str, *, forwarded: bool) -> list[list[str]]:
    """Let xauth canonicalize DISPLAY, then validate only its matching records."""
    try:
        if forwarded:
            _host, port, _screen = x11_relay.parse_forwarded_display(display)
            expected_number = port - 6000
        else:
            match = re.fullmatch(r"(?:unix)?:([0-9]+)(?:\.[0-9]+)?", display)
            if not match:
                raise ValueError("local DISPLAY is malformed")
            expected_number = int(match.group(1))
    except x11_relay.X11RelayError as error:
        raise ValueError("forwarded DISPLAY is malformed") from error

    result = command_result(["xauth", "nlist", display], check=False)
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if result.returncode or not lines:
        return []
    parsed = [parse_xauthority_record(line) for line in lines]
    if any(int(display_number) != expected_number for _fields, display_number, _protocol in parsed):
        raise ValueError("xauth returned an entry for a different display number")
    if forwarded:
        if len(parsed) != 1:
            raise ValueError("forwarded DISPLAY has ambiguous Xauthority entries")
        if parsed[0][2] != "MIT-MAGIC-COOKIE-1":
            raise ValueError("forwarded DISPLAY has no MIT-MAGIC-COOKIE-1 entry")
    elif not any(protocol == "MIT-MAGIC-COOKIE-1" for _fields, _number, protocol in parsed):
        return []
    return [fields for fields, _number, _protocol in parsed]


def local_x11_info(display: str) -> dict[str, str]:
    if not display:
        raise PrerequisiteError("native X11 requires a local or authenticated SSH-forwarded DISPLAY")
    forwarded = False
    try:
        x11_relay.parse_forwarded_display(display)
        forwarded = True
    except x11_relay.X11RelayError as error:
        if not display.startswith((":", "unix:")):
            raise PrerequisiteError(str(error)) from error
    require_tools("xauth", "xdpyinfo", "xwininfo", "xwd")
    server = command_result(["xdpyinfo", "-display", display], timeout=10, check=False)
    if server.returncode:
        raise PrerequisiteError(f"host X11 display is inaccessible: {server.stderr.strip()}")
    if not forwarded:
        ps = command_result(["ps", "-eo", "args"], check=False).stdout
        display_number = display.rsplit(":", 1)[-1].split(".", 1)[0]
        if re.search(rf"(?:^|\s)Xvfb\s+:{re.escape(display_number)}(?:\s|$)", ps, re.MULTILINE):
            raise PrerequisiteError("real Linux desktop check rejects Xvfb; use the automated X11 integration test for Xvfb")
    try:
        authority_records = xauthority_records_for_display(display, forwarded=forwarded)
    except ValueError as error:
        raise PrerequisiteError(f"host DISPLAY Xauthority is invalid: {error}") from error
    if not authority_records:
        raise PrerequisiteError("host DISPLAY has no Xauthority cookie; refusing xhost fallback")
    vendor = next((line.strip() for line in server.stdout.splitlines() if "vendor string:" in line), "unknown")
    release = next((line.strip() for line in server.stdout.splitlines() if "vendor release number:" in line), "unknown")
    return {"x_server": vendor, "x_server_release": release,
            "display": re.sub(r"^[^:]*", "", display),
            "display_transport": "ssh-x11-forwarding" if forwarded else "local-x11"}


def detect_host(scope: str) -> tuple[dict[str, Any], str]:
    system = platform.system()
    if scope in ("linux-x11", "ledger-linux") and system != "Linux":
        raise PrerequisiteError(f"{scope} requires Linux; observed {system}")
    if scope == "mac-xquartz" and system != "Darwin":
        raise PrerequisiteError(f"mac-xquartz requires macOS; observed {system}")
    try:
        context = json.loads(checked(["docker", "context", "inspect", "default", "--format", "{{json .Endpoints.docker}}"] ))
    except (RunnerError, json.JSONDecodeError) as error:
        raise PrerequisiteError(f"Docker Engine is unavailable: {error}") from error
    if not str(context.get("Host", "")).startswith("unix://"):
        raise PrerequisiteError("platform checks require a local Docker Engine/Desktop Unix socket")
    try:
        engine_os = checked(["docker", "info", "--format", "{{.OperatingSystem}}"])
        engine_version = checked(["docker", "version", "--format", "{{.Server.Version}}"])
        compose_version = checked(["docker", "compose", "version", "--short"])
    except RunnerError as error:
        raise PrerequisiteError(f"Docker Desktop/Engine and Compose must be available: {error}") from error
    values: dict[str, Any] = {"host_os": f"{system} {platform.release()}", "architecture": platform.machine(),
                              "docker_engine": f"{engine_os}|{engine_version}", "compose": compose_version}
    if scope == "linux-x11":
        display = os.environ.get("DISPLAY", "")
        values.update(local_x11_info(display))
        return values, display
    if scope == "mac-xquartz":
        values["host_os"] = f"Darwin {platform.mac_ver()[0]}"
        require_tools("defaults", "xauth", "lsof", "pgrep", "open", "osascript", "xhost", "xwininfo", "xwd")
        if "docker desktop" not in engine_os.lower():
            raise PrerequisiteError("macOS XQuartz checks require Docker Desktop")
        app = Path(os.environ.get("XQUARTZ_APP", "/Applications/Utilities/XQuartz.app"))
        plist = app / "Contents/Info.plist"
        if not plist.is_file():
            raise PrerequisiteError("XQuartz is not installed at the supported application path")
        import plistlib
        info = plistlib.loads(plist.read_bytes())
        values["docker_desktop"] = f"{engine_os}|{engine_version}"
        values["xquartz"] = str(info.get("CFBundleShortVersionString", "unknown"))
        display = os.environ.get("DISPLAY", ":0")
        process_name = xquartz_process_name()
        cookie_present = xauthority_has_mit_cookie(display)
        values["xauthority_cookie_present_before"] = cookie_present
        values["xquartz_running_before"] = process_name is not None
        # A stopped XQuartz server cannot yet have a usable display cookie.
        # mac-gui.sh starts it and validates the cookie before Docker launch.
        # If it is already running, missing authority is a real preflight error.
        if process_name is not None and not cookie_present:
            raise PrerequisiteError(f"XQuartz has no MIT-MAGIC-COOKIE-1 authority for DISPLAY={display}")
        values["display"] = "host.docker.internal:0"
        values["nolisten_tcp_before"] = command_result(["defaults", "read", "org.xquartz.X11", "nolisten_tcp"], check=False).stdout.strip() or "unset"
        values["xhost_access_sha256_before"] = xhost_access_fingerprint()
        return values, display
    display = os.environ.get("DISPLAY", "")
    values.update(local_x11_info(display))
    require_tools("lsusb")
    if "docker desktop" in engine_os.lower():
        raise PrerequisiteError("Ledger checks require native Linux Docker Engine, not Docker Desktop")
    if not Path("/dev/bus/usb").is_dir():
        raise PrerequisiteError("host USB device nodes are unavailable")
    devices = checked(["lsusb"])
    if not re.search(r"ID (?:2c97:[0-9a-fA-F]{4}|2581:(?:1807|2b7c|3b7c|4b7c))", devices, re.IGNORECASE):
        raise PrerequisiteError("no supported physical Ledger USB device was detected")
    usb_gid = os.environ.get("HW_USB_GID", "")
    if not re.fullmatch(r"[0-9]+", usb_gid):
        raise PrerequisiteError("set HW_USB_GID to the numeric group owning the Ledger USB device node")
    nodes = []
    for line in devices.splitlines():
        match = re.search(r"Bus\s+(\d+)\s+Device\s+(\d+):\s+ID (?:2c97:[0-9a-fA-F]{4}|2581:(?:1807|2b7c|3b7c|4b7c))", line, re.IGNORECASE)
        if match:
            node = Path("/dev/bus/usb") / match.group(1) / match.group(2)
            if node.exists():
                nodes.append(node)
    groups = {node.stat().st_gid for node in nodes}
    if not groups:
        raise PrerequisiteError("no supported physical Ledger USB device node was resolved")
    if len(groups) != 1 or int(usb_gid) not in groups:
        raise PrerequisiteError("HW_USB_GID must match the host group owning the supported Ledger USB node")
    values["kernel"] = platform.release()
    values["usb_group"] = usb_gid
    return values, display


def dotenv(path: Path) -> dict[str, str]:
    if not path.is_file():
        raise PrerequisiteError(f"missing required configuration file: {path}")
    result = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def make_linux_authority(display: str, directory: Path,
                        container_display_number: int | None = None) -> Path:
    try:
        x11_relay.parse_forwarded_display(display)
        forwarded = True
    except x11_relay.X11RelayError:
        forwarded = False
    try:
        records = xauthority_records_for_display(display, forwarded=forwarded)
    except ValueError as error:
        raise RunnerError(f"host DISPLAY Xauthority is invalid: {error}") from error
    if not records:
        raise RunnerError("host DISPLAY has no Xauthority cookie; refusing xhost fallback")
    if forwarded and container_display_number is not None:
        if not 0 <= container_display_number <= 65535:
            raise RunnerError("container X11 display number is outside the Xauthority range")
        number = str(container_display_number).encode("ascii").hex()
        for record in records:
            record[3] = f"{len(str(container_display_number)):04x}"
            record[4] = number
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = directory / "authority"
    wildcard = "\n".join(" ".join(["ffff", *record[1:]]) for record in records) + "\n"
    merged = command_result(["xauth", "-f", str(target), "nmerge", "-"],
                            input_text=wildcard, check=False)
    if merged.returncode or not target.is_file() or target.stat().st_size == 0:
        raise RunnerError("unable to create the task-scoped Xauthority file")
    target.chmod(0o644)
    return target


def negative_display(image: str, display: str, authority: Path | None, expected: str,
                     env: dict[str, str], socket_dir: Path = Path("/tmp/.X11-unix")) -> None:
    command = ["docker", "run", "--rm", "--pull=never", "--network", "none"]
    if socket_dir.is_dir():
        command += ["--mount", f"type=bind,src={socket_dir},dst=/tmp/.X11-unix,readonly"]
    if authority:
        command += ["--mount", f"type=bind,src={authority},dst=/home/electroncash/.Xauthority,readonly"]
    command += ["-e", "MODE=gui", "-e", f"DISPLAY={display}", "-e", "USE_TOR=false",
                "-e", "CASHFUSION_ENABLED=false", image]
    result = run(command, env=env, timeout=30)
    output = result.stdout + result.stderr
    if result.returncode == 0 or expected not in output or "noVNC" in output or "websockify" in output:
        raise RunnerError(f"native GUI negative display control failed: expected {expected!r}; got {output[-1500:]}")


def probe_container_display(image: str, display: str, authority: Path, socket_dir: Path,
                            owner_token: str, env: dict[str, str]) -> None:
    """Verify X11 authentication and the relay across the actual Docker boundary."""
    metadata = socket_dir.stat()
    socket_path = socket_dir / ("X" + display.rsplit(":", 1)[-1].split(".", 1)[0])
    if (metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o711 or
            not socket_path.is_socket() or stat.S_IMODE(socket_path.stat().st_mode) != 0o666):
        raise RunnerError("private forwarded-X11 socket ownership or permissions are invalid")
    if authority.stat().st_mode & 0o777 != 0o644:
        raise RunnerError("task Xauthority file is not readable by the non-root wallet user")
    command = ["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
               "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
               "--label", f"{docker_ownership.OWNER_LABEL}={owner_token}",
               "--mount", f"type=bind,src={socket_dir},dst=/tmp/.X11-unix,readonly",
               "--mount", f"type=bind,src={authority},dst=/home/electroncash/.Xauthority,readonly",
               "-e", f"DISPLAY={display}", "-e", "XAUTHORITY=/home/electroncash/.Xauthority",
               "--entrypoint", "xdpyinfo", image, "-display", display]
    checked(command, env=env, timeout=20)


def compose_args(scope: str, project: str, env_file: Path,
                platform_override: Path | None = None) -> list[str]:
    args = ["docker", "compose", "--project-directory", str(ROOT), "--env-file", str(env_file), "-p", project,
            "-f", str(ROOT / "docker-compose.yml"), "-f", str(ROOT / "docker-compose.gui.yml")]
    if scope == "ledger-linux":
        args += ["-f", str(ROOT / "docker-compose.hw.yml")]
    if platform_override is not None:
        args += ["-f", str(platform_override)]
    return args


def platform_compose_down(scope: str, project: str, env_file: Path,
                          platform_override: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    """Stop this task using the same resolved Compose environment as startup."""
    return command_result([*compose_args(scope, project, env_file, platform_override),
                           "down", "--volumes", "--remove-orphans"],
                          env=env, check=False, timeout=120)


def platform_targets(scope: str, machine: str | None = None) -> dict[str, str]:
    if scope not in SCOPES:
        raise RunnerError(f"unsupported platform scope: {scope}")
    targets = {"electron-cash": IMAGE_PLATFORM, "tor-proxy": IMAGE_PLATFORM}
    if scope == "mac-xquartz":
        host_arch = machine or platform.machine()
        if host_arch in ("arm64", "aarch64"):
            # Electron Cash remains the supported amd64 product image. Use a
            # native-architecture Tor helper so its seccomp sandbox works on
            # Apple Silicon Docker Desktop without weakening container policy.
            targets["tor-proxy"] = "linux/arm64"
        elif host_arch not in ("x86_64", "amd64"):
            raise PrerequisiteError(f"unsupported macOS architecture for XQuartz checks: {host_arch}")
    return targets


def prepare_platform_images(scope: str, compose: list[str], platform_override: Path,
                           image_platforms: dict[str, str], env: dict[str, str],
                           owner_token: str, claims: list[dict[str, Any]],
                           owner_registry: Path) -> tuple[dict[str, str], dict[str, str]]:
    """Resolve content-addressed build tags and identify reusable local images."""
    resolved_compose = json.loads(checked([*compose, "config", "--format", "json"], env=env, timeout=30))
    build_compose_files = [ROOT / "docker-compose.yml", ROOT / "docker-compose.gui.yml"]
    if scope == "ledger-linux":
        build_compose_files.append(ROOT / "docker-compose.hw.yml")
    build_compose_files.append(platform_override)
    ec_variant = "electron-cash-hw" if scope == "ledger-linux" else "electron-cash-normal"
    ec_build = ci_validation.image_build_configuration(
        resolved_compose, "electron-cash", env["ELECTRON_CASH_IMAGE"], variant=ec_variant,
        compose_files=build_compose_files)
    tor_build = ci_validation.image_build_configuration(
        resolved_compose, "tor-proxy", env["TOR_IMAGE"], variant="tor-proxy",
        compose_files=build_compose_files)
    image_refs = {
        "electron-cash": f"electron-cash-platform:{ec_build['configuration_sha256'][:32]}",
        "tor-proxy": f"bchforge/electron-cash-docker-tor-platform:{tor_build['configuration_sha256'][:32]}",
    }
    env["ELECTRON_CASH_IMAGE"] = image_refs["electron-cash"]
    if scope == "ledger-linux":
        env["ECD_HW_IMAGE"] = image_refs["electron-cash"]
    env["TOR_IMAGE"] = image_refs["tor-proxy"]
    reusable_images = {}
    for service_name, image_ref in image_refs.items():
        expected_platform = image_platforms[service_name]
        inspected = run(["docker", "image", "inspect", image_ref], env=env, timeout=30)
        if inspected.returncode == 0:
            image = json.loads(inspected.stdout)[0]
            actual_platform = f"{image.get('Os')}/{image.get('Architecture')}"
            if actual_platform != expected_platform:
                raise RunnerError(f"cached {service_name} image platform {actual_platform} does not match "
                                  f"{expected_platform}: {image_ref}")
            reusable_images[service_name] = image["Id"]
            print(f"[platform] reusing matching {service_name} image {image['Id']} ({actual_platform})",
                  flush=True)
            continue
        missing_output = (inspected.stdout + inspected.stderr).lower()
        if "no such image" not in missing_output and "no such object" not in missing_output:
            raise RunnerError(f"unable to inspect reusable {service_name} image {image_ref}: "
                              f"{(inspected.stdout + inspected.stderr)[-1000:]}")
        image_claim = docker_ownership.reserve_claim("image", image_ref, owner_token)
        claims.append(image_claim)
        with owner_registry.open("a", encoding="utf-8") as output:
            output.write(json.dumps(image_claim, sort_keys=True, separators=(",", ":")) + "\n")
    return image_refs, reusable_images


def prepare_platform_display(scope: str, display: str, environment_info: dict[str, Any],
                             directory: Path, relay_socket_name: str = "X0"
                             ) -> tuple[Path, str, Path, x11_relay.ForwardedX11Relay | None]:
    """Create session-only Xauthority and optional SSH-forward relay paths."""
    authority = Path(os.environ.get("XAUTHORITY", str(Path.home() / ".Xauthority")))
    socket_dir = Path("/tmp/.X11-unix")
    container_display = display
    relay = None
    if scope in ("linux-x11", "ledger-linux"):
        forwarded = environment_info.get("display_transport") == "ssh-x11-forwarding"
        if forwarded:
            relay_host, relay_port, screen = x11_relay.parse_forwarded_display(display)
            socket_dir = directory / "sockets"
            socket_dir.mkdir(mode=0o711)
            socket_dir.chmod(0o711)
            socket_path = socket_dir / relay_socket_name
            container_display_number = x11_relay.display_number_from_socket(socket_path)
            container_display = f":{container_display_number}.{screen}"
            authority = make_linux_authority(display, directory, container_display_number)
            relay = x11_relay.ForwardedX11Relay(socket_path, relay_host, relay_port)
        else:
            authority = make_linux_authority(display, directory)
    return authority, container_display, socket_dir, relay


def write_platform_override(scope: str, destination: Path,
                           machine: str | None = None) -> tuple[Path, dict[str, str]]:
    targets = platform_targets(scope, machine)
    document = {"services": {name: {"platform": target} for name, target in targets.items()}}
    destination.write_text(json.dumps(document, separators=(",", ":")) + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination, targets


def write_platform_display_override(destination: Path, authority: Path,
                                    socket_dir: Path) -> Path:
    """Keep the maintainer X11/SSH relay path separate from local GUI preparation."""
    document = {"services": {"electron-cash": {
        "environment": {"XAUTHORITY": "/home/electroncash/.Xauthority"},
        "volumes": [
            {"type": "volume", "source": "electron-cash-data",
             "target": "/home/electroncash/.electron-cash"},
            {"type": "bind", "source": str(authority),
             "target": "/home/electroncash/.Xauthority", "read_only": True,
             "bind": {"create_host_path": False}},
            {"type": "bind", "source": str(socket_dir),
             "target": "/tmp/.X11-unix", "read_only": True,
             "bind": {"create_host_path": False}},
        ],
    }}}
    rendered = json.dumps(document, separators=(",", ":")).replace(
        '"volumes":[', '"volumes": !override [', 1)
    destination.write_text(rendered + "\n", encoding="utf-8")
    destination.chmod(0o600)
    return destination


def container_for(project: str, service: str = "electron-cash") -> str | None:
    result = run(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}",
                  "--filter", f"label=com.docker.compose.service={service}"])
    return result.stdout.strip() or None


def list_services(project: str) -> list[str]:
    result = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
                  "--format", "{{.Label \"com.docker.compose.service\"}}"])
    return sorted(line for line in result.stdout.splitlines() if line)


def wait_tor(project: str, timeout: int = 90) -> str:
    container = container_for(project, "tor-proxy")
    if not container:
        raise RunnerError("Tor sidecar did not start")
    deadline = time.monotonic() + timeout
    status = None
    while time.monotonic() < deadline:
        status = run(["docker", "inspect", "--format", "{{.State.Health.Status}}", container])
        if status.stdout.strip() == "healthy":
            return container
        time.sleep(1)
    raise RunnerError("Tor sidecar did not become healthy")


def tor_sock_check(container: str) -> None:
    code = ("import socket; s=socket.create_connection(('tor-proxy',9050),5); "
            "s.sendall(b'\\x05\\x01\\x00'); r=s.recv(2); s.close(); assert r==b'\\x05\\x00',r")
    checked(["docker", "exec", "--user", "10001:10001", container,
             "/opt/electroncash-venv/bin/python", "-c", code], timeout=15)


def unpack_xwd_header(raw: bytes) -> tuple[int, ...]:
    """Parse an XWD header using the byte order actually present in the file."""
    if len(raw) < 100:
        raise RunnerError("XWD window screenshot is truncated")
    native_order = "<" if sys.byteorder == "little" else ">"
    header = struct.unpack(native_order + "25I", raw[:100])
    if header[1] == 7:
        return header
    other_order = ">" if native_order == "<" else "<"
    swapped = struct.unpack(other_order + "25I", raw[:100])
    if swapped[1] == 7:
        return swapped
    raise RunnerError(f"unsupported XWD file version: {header[1]} (byte-swapped={swapped[1]})")


def capture_window(display: str, window_id: str, env: dict[str, str], target: Path) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    header = None
    raw = b""
    pixels = b""
    pixel_start = 0
    distinct_bytes = 0
    while time.monotonic() < deadline:
        result = subprocess.run(["xwd", "-display", display, "-id", window_id, "-silent"],
                                env=env, capture_output=True, timeout=10, check=False)
        if result.returncode:
            raise RunnerError(f"unable to capture Electron Cash window: {result.stderr.decode(errors='replace')}")
        raw = result.stdout
        if len(raw) < 100:
            raise RunnerError("XWD window screenshot is truncated")
        header = unpack_xwd_header(raw)
        pixel_start = header[0] + header[19] * 12
        pixels = raw[pixel_start:]
        distinct_bytes = len(set(pixels))
        if pixels and distinct_bytes >= 2:
            break
        time.sleep(1)
    if header is None or not pixels or distinct_bytes < 2:
        frame = {"width": header[4], "height": header[5], "pixmap_format": header[2],
                 "depth": header[3], "bits_per_pixel": header[11], "bytes_per_line": header[12],
                 "ncolors": header[19], "pixel_start": pixel_start, "pixel_bytes": len(pixels),
                 "distinct_pixel_bytes": distinct_bytes} if header else {}
        raise RunnerError(f"Electron Cash X11 window remained blank in XWD capture: {frame}")
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    target.write_bytes(raw)
    os.chmod(target, 0o600)
    return {"window_id": window_id, "width": header[4], "height": header[5]}


def ledger_probe_script() -> str:
    """Probe the pinned Electron Cash Ledger_Client with a read-only BCH path."""
    return r'''import json
from types import SimpleNamespace
import hid
from electroncash_plugins.ledger.ledger import LedgerPlugin
supported=set(LedgerPlugin.DEVICE_IDS)
for item in hid.enumerate():
    product=(item.get("vendor_id"),item.get("product_id"))
    if product not in supported: continue
    info=SimpleNamespace(product_key=product,interface_number=item.get("interface_number",0),
                         usage_page=item.get("usage_page",0),path=item["path"])
    plugin=object.__new__(LedgerPlugin)
    plugin.device="Ledger"
    client=LedgerPlugin.create_client(plugin,info,None)
    if client is None: continue
    result=None
    try:
        # The pinned plugin factory wraps its raw HIDDongleHIDAPI in Ledger_Client,
        # whose dongleObject is the pinned btchip-python backend.
        client.checkDevice()
        backend=client.dongleObject
        if not client.supports_bitcoin_cash():
            raise RuntimeError("Ledger firmware does not support Bitcoin Cash")
        firmware=backend.getFirmwareVersion()
        firmware_version=firmware.get("version")
        if not isinstance(firmware_version,str) or not firmware_version:
            raise RuntimeError("Ledger firmware version was not returned")
        # No display/sign request; retain no public derivation material.
        result=backend.getWalletPublicKey("44'/145'/0'",showOnScreen=False)
        valid=False
        if isinstance(result,dict):
            public_key=result.get("publicKey")
            address=result.get("address")
            chain_code=result.get("chainCode")
            valid=(isinstance(public_key,(bytes,bytearray,list,tuple)) and len(public_key)>0 and
                   isinstance(address,str) and bool(address) and
                   isinstance(chain_code,(bytes,bytearray,list,tuple)) and len(chain_code)==32)
            del public_key,address,chain_code
            result.clear()
        if not valid:
            raise RuntimeError("Ledger BCH public-path response had an unexpected shape")
        report={"model_id":f"{product[0]:04x}:{product[1]:04x}",
                "firmware":firmware_version,
                "bch_app":"compatible",
                "read_only_bch_path":"passed"}
    finally:
        client.close()
    print(json.dumps(report))
    raise SystemExit(0)
raise SystemExit("no supported Ledger HID device found")'''


def ledger_probe(image: str, usb_gid: str, owner_token: str) -> dict[str, Any]:
    script = ledger_probe_script()
    command = ["docker", "run", "--label", f"{docker_ownership.OWNER_LABEL}={owner_token}",
               "--rm", "--pull=never", "--network", "none", "--read-only",
               "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
               "-e", "PYTHONDONTWRITEBYTECODE=1", "--group-add", usb_gid,
               "--device", "/dev/bus/usb:/dev/bus/usb",
               "--device-cgroup-rule", "c 189:* rw", "--entrypoint", "/opt/electroncash-venv/bin/python",
               image, "-c", script]
    try:
        output = checked(command, timeout=60)
        return json.loads(output.splitlines()[-1])
    except (RunnerError, json.JSONDecodeError, IndexError) as error:
        raise RunnerError(f"safe Ledger plugin transport probe failed: {error}") from error


def runtime_cleanup_targets(owner_token: str, claims: list[dict[str, Any]], *,
                           containers: list[dict[str, Any]], networks: list[dict[str, Any]],
                           volumes: list[dict[str, Any]]) -> dict[str, list[str]]:
    """Select disposable runtime resources while retaining reusable image artifacts."""
    return docker_ownership.select_cleanup_targets(
        owner_token, claims, containers=containers, networks=networks, volumes=volumes, images=[])


def cleanup_task_resources(project: str, owner_token: str, claims: list[dict[str, Any]],
                           preexisting_image_ids: set[str]) -> dict[str, Any]:
    attempts = []
    failures = []
    removed_resources = []
    def cleanup_command(command: list[str], timeout: int = 60) -> subprocess.CompletedProcess[str]:
        try:
            return run(command, timeout=timeout)
        except (OSError, subprocess.TimeoutExpired):
            failures.append("cleanup command could not be completed")
            return subprocess.CompletedProcess(command, 125, "", "cleanup command failed")

    def ids(command: list[str], kind: str) -> list[str]:
        result = cleanup_command(command)
        if result.returncode:
            failures.append(f"unable to enumerate owned {kind}")
            return []
        return result.stdout.split()

    container_ids = set(ids(["docker", "ps", "-aq", "--filter",
                             f"label={docker_ownership.PROJECT_LABEL}={project}"], "Compose containers"))
    container_ids.update(ids(["docker", "ps", "-aq", "--filter",
                              f"label={docker_ownership.OWNER_LABEL}={owner_token}"], "owner-labeled containers"))
    networks = set(ids(["docker", "network", "ls", "-q", "--filter",
                        f"label={docker_ownership.PROJECT_LABEL}={project}"], "Compose networks"))
    networks.update(ids(["docker", "network", "ls", "-q", "--filter",
                         f"label={docker_ownership.OWNER_LABEL}={owner_token}"], "owner-labeled networks"))

    volume_names = {claim["name"] for claim in claims if claim.get("kind") == "volume" and
                    claim.get("owner_token") == owner_token}
    volume_names.update(ids(["docker", "volume", "ls", "-q", "--filter",
                             f"label={docker_ownership.OWNER_LABEL}={owner_token}"], "owner-labeled volumes"))
    volumes = []
    for name in sorted(volume_names):
        inspected = cleanup_command(["docker", "volume", "inspect", name])
        if inspected.returncode:
            if "no such volume" not in inspected.stderr.lower():
                failures.append(f"unable to inspect claimed volume {name}")
            continue
        item = json.loads(inspected.stdout)[0]
        volumes.append({"name": item["Name"], "labels": item.get("Labels") or {}})

    image_claims = [claim for claim in claims if claim.get("kind") == "image" and
                    claim.get("owner_token") == owner_token]
    for claim in image_claims:
        if claim.get("build_attempted") is True and not claim.get("expected_id"):
            inspected = cleanup_command(["docker", "image", "inspect", claim["name"]])
            if inspected.returncode == 0:
                claim["expected_id"] = json.loads(inspected.stdout)[0].get("Id")

    container_items = []
    if container_ids:
        inspected = cleanup_command(["docker", "inspect", *sorted(container_ids)])
        if inspected.returncode:
            failures.append("unable to inspect candidate containers")
        else:
            container_items = [{"id": item["Id"], "labels": item.get("Config", {}).get("Labels") or {}}
                               for item in json.loads(inspected.stdout)]
    network_items = []
    if networks:
        inspected = cleanup_command(["docker", "network", "inspect", *sorted(networks)])
        if inspected.returncode:
            failures.append("unable to inspect candidate networks")
        else:
            network_items = [{"id": item["Id"], "name": item.get("Name"), "labels": item.get("Labels") or {}}
                             for item in json.loads(inspected.stdout)]
    plan = runtime_cleanup_targets(owner_token, claims, containers=container_items,
                                   networks=network_items, volumes=volumes)
    for container_id in plan["containers"]:
        result = cleanup_command(["docker", "rm", "-f", container_id], timeout=120)
        attempts.append({"kind": "container", "id": container_id, "returncode": result.returncode})
        if result.returncode:
            failures.append(f"unable to remove owned container ID {container_id}")
        else:
            item = next((value for value in container_items if value["id"] == container_id), {})
            removed_resources.append({"kind": "container", "id": container_id,
                                      "labels": item.get("labels"), "proof": "owner token/project claim"})
    for network_id in plan["networks"]:
        result = cleanup_command(["docker", "network", "rm", network_id], timeout=60)
        attempts.append({"kind": "network", "id": network_id, "returncode": result.returncode})
        if result.returncode:
            failures.append(f"unable to remove owned network ID {network_id}")
        else:
            item = next((value for value in network_items if value["id"] == network_id), {})
            removed_resources.append({"kind": "network", "id": network_id,
                                      "labels": item.get("labels"), "proof": "owner token/project claim"})
    for volume in plan["volumes"]:
        result = cleanup_command(["docker", "volume", "rm", volume], timeout=60)
        attempts.append({"kind": "volume", "name": volume, "returncode": result.returncode})
        if result.returncode:
            failures.append(f"unable to remove owned volume {volume}")
        else:
            item = next((value for value in volumes if value["name"] == volume), {})
            removed_resources.append({"kind": "volume", "name": volume,
                                      "labels": item.get("labels"), "proof": "owner token/project claim"})
    retained_images = []
    for name in volume_names:
        check = cleanup_command(["docker", "volume", "inspect", name])
        if check.returncode == 0:
            failures.append(f"owned or claimed volume remains after cleanup: {name}")
        elif "no such volume" not in check.stderr.lower():
            failures.append(f"unable to verify volume cleanup: {name}")
    for claim in image_claims:
        check = cleanup_command(["docker", "image", "inspect", claim["name"]])
        if check.returncode:
            if "no such image" not in check.stderr.lower() and "no such object" not in check.stderr.lower():
                failures.append(f"unable to verify retained image: {claim['name']}")
            continue
        image = json.loads(check.stdout)[0]
        image_id = image.get("Id")
        expected_id = claim.get("expected_id")
        if expected_id and image_id != expected_id:
            failures.append(f"candidate image identity changed; retained {claim['name']}")
            continue
        retained_images.append({"name": claim["name"], "id": image_id,
                                "preexisting_image_object": image_id in preexisting_image_ids})
    remaining_containers = cleanup_command(["docker", "ps", "-aq", "--filter",
        f"label={docker_ownership.PROJECT_LABEL}={project}"])
    if remaining_containers.returncode or remaining_containers.stdout.split():
        failures.append("owned Compose containers remain or cannot be verified")
    remaining_containers = cleanup_command(["docker", "ps", "-aq", "--filter",
        f"label={docker_ownership.OWNER_LABEL}={owner_token}"])
    if remaining_containers.returncode or remaining_containers.stdout.split():
        failures.append("owner-labeled task containers remain or cannot be verified")
    remaining_networks = cleanup_command(["docker", "network", "ls", "-q", "--filter",
        f"label={docker_ownership.PROJECT_LABEL}={project}"])
    if remaining_networks.returncode or remaining_networks.stdout.split():
        failures.append("owned Compose networks remain or cannot be verified")
    remaining_networks = cleanup_command(["docker", "network", "ls", "-q", "--filter",
        f"label={docker_ownership.OWNER_LABEL}={owner_token}"])
    if remaining_networks.returncode or remaining_networks.stdout.split():
        failures.append("owner-labeled task networks remain or cannot be verified")
    return {"status": "PASS" if not failures else "FAIL", "owner_token": owner_token,
            "claims": claims, "selected": plan, "attempts": attempts,
            "removed_resources": removed_resources,
            "retained_images": retained_images,
            "failures": failures, "scope": project}


def wait_window(display: str, timeout: int,
                relay: x11_relay.ForwardedX11Relay | None = None) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if relay is not None:
            relay.check()
        result = command_result(["xwininfo", "-display", display, "-root", "-tree"], check=False, timeout=10)
        match = re.search(r'^\s*(0x[0-9a-fA-F]+)\s+.*Electron Cash', result.stdout, re.MULTILINE)
        if result.returncode == 0 and match:
            return match.group(1)
        time.sleep(1)
    server = command_result(["xdpyinfo", "-display", display], timeout=10, check=False)
    windows = command_result(["xwininfo", "-display", display, "-root", "-tree"],
                             timeout=10, check=False)
    server_state = "reachable" if server.returncode == 0 else server.stderr.strip()[-500:]
    window_state = windows.stdout.strip()[-1500:] or windows.stderr.strip()[-500:] or "unavailable"
    raise RunnerError("Electron Cash window was not observed; live X11 state: "
                      f"server={server_state}; root window tree={window_state}")


def verify_platform_wallet_marker(image: str, wallet: str, marker: str,
                                 env: dict[str, str]) -> None:
    """Read the persisted task marker without relaunching the interactive GUI."""
    relative_marker = Path(marker).relative_to("/home/electroncash/.electron-cash")
    output = checked([
        "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
        "--cap-drop=ALL", "--security-opt", "no-new-privileges:true", "--user", "10001:10001",
        "--mount", f"type=volume,src={wallet},dst=/wallet,readonly",
        "--entrypoint", "/opt/electroncash-venv/bin/python", image,
        "-c", "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text())",
        f"/wallet/{relative_marker}",
    ], env=env, timeout=60)
    if output.strip() != "retained":
        raise RunnerError("disposable wallet marker did not persist after clean GUI shutdown")


def report_platform_result(scope: str, cleanup_result: dict[str, Any],
                           not_run_error: str | None, result_error: str | None,
                           image_ids: dict[str, str], image_platforms: dict[str, str]) -> int:
    """Format the final outcome only after the run's finally cleanup completed."""
    if cleanup_result["status"] != "PASS":
        print(f"FAIL platform-run {scope}: task-owned cleanup did not pass: "
              f"{cleanup_result.get('failures', [])}", file=sys.stderr, flush=True)
        return 1
    if not_run_error:
        print(f"NOT RUN platform-run {scope}: {not_run_error}", file=sys.stderr, flush=True)
        return 2
    if result_error:
        print(f"FAIL platform-run {scope}: {result_error}", file=sys.stderr, flush=True)
        return 1
    for name, image_id in sorted(image_ids.items()):
        print(f"[platform] tested image {name}={image_id} platform={image_platforms[name]}", flush=True)
    print(f"PASS platform-run {scope}; NETWORK=chipnet; cleanup and host restoration passed", flush=True)
    return 0


def run_platform(scope: str, timeout: int) -> int:
    if scope not in SCOPES:
        raise RunnerError(f"unsupported platform scope: {scope}")
    environment_info, display = detect_host(scope)
    docker_root = checked(["docker", "info", "--format", "{{.DockerRootDir}}"])
    ci_validation.configure_disk_storage_paths(docker_root.strip())
    env_file = ENV_LOCAL if scope == "mac-xquartz" else ENV_EXAMPLE
    pins = dotenv(env_file)
    approved = dotenv(ENV_EXAMPLE)
    for name in ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256", "TOR_VERSION", "TOR_SOURCE_SHA256"):
        if pins.get(name) != approved.get(name):
            raise PrerequisiteError(f"{env_file.name} {name} differs from the approved v0.4 pin")
    print(f"[platform] host={environment_info['host_os']} arch={environment_info['architecture']} "
          f"docker={environment_info['docker_engine']} compose={environment_info['compose']}", flush=True)
    if environment_info.get("display_transport") == "ssh-x11-forwarding":
        print(f"[platform] display transport=SSH X11 forwarding; X server={environment_info['x_server']}",
              flush=True)
    if scope == "mac-xquartz":
        print(f"[platform] XQuartz={environment_info['xquartz']} "
              f"initially_running={environment_info['xquartz_running_before']}", flush=True)
    owner_token = uuid.uuid4().hex
    project = "ecd-real-" + scope.replace("_", "-") + "-" + owner_token
    wallet = project + "-wallet"
    tor_volume = project + "-tor"
    # Replaced below with content-addressed references derived from the resolved
    # Compose build configuration. Stable references let a later platform run
    # reuse an image only when its actual build inputs still match.
    ec_image = "electron-cash-platform:pending"
    tor_image = "bchforge/electron-cash-docker-tor-platform:pending"
    claims = [docker_ownership.reserve_claim("project", project, owner_token),
              docker_ownership.reserve_claim("volume", wallet, owner_token),
              docker_ownership.reserve_claim("volume", tor_volume, owner_token)]
    preexisting_image_ids = set(checked(["docker", "image", "ls", "-aq", "--no-trunc"]).splitlines())
    builder, builder_lock, builder_record = ci_validation.ensure_task_buildx_builder(
        report_dir=ci_validation.task_builder_record_path().parent, manifest=None, log_path=None)
    lock_released = False

    def release_builder_lock() -> None:
        nonlocal lock_released
        if not lock_released:
            fcntl.flock(builder_lock, fcntl.LOCK_UN)
            os.close(builder_lock)
            lock_released = True

    atexit.register(release_builder_lock)
    display_dir = Path(tempfile.mkdtemp(prefix="ecd-platform-xauth-"))
    relay: x11_relay.ForwardedX11Relay | None = None
    socket_dir = Path("/tmp/.X11-unix")
    container_display = display

    def cleanup_display_transport() -> None:
        if relay is not None:
            relay.close()
        shutil.rmtree(display_dir, ignore_errors=True)

    atexit.register(cleanup_display_transport)
    try:
        platform_override, image_platforms = write_platform_override(
            scope, display_dir / "image-platform.yml")
        authority, container_display, socket_dir, relay = prepare_platform_display(
            scope, display, environment_info, display_dir)
        if scope in ("linux-x11", "ledger-linux"):
            write_platform_display_override(platform_override, authority, socket_dir)
    except Exception:
        cleanup_display_transport()
        atexit.unregister(cleanup_display_transport)
        release_builder_lock()
        raise
    environment_info["image_platforms"] = image_platforms
    if scope == "ledger-linux":
        environment_info["ledger_model"] = "pending safe device probe"
        environment_info["firmware"] = "pending safe device probe"
        environment_info["bch_app"] = "pending safe device probe"
    image_ids: dict[str, str] = {}
    cleanup_result = {"status": "NOT_RUN", "owned_project": project, "removed": []}
    compose_down_returncode = None
    compose_down_output = ""
    process: subprocess.Popen | None = None
    launch: list[str] = []
    result_error: str | None = None
    not_run_error: str | None = None
    with tempfile.TemporaryDirectory(prefix="ecd-platform-run-") as temporary_dir:
        task_tmp = Path(temporary_dir)
        docker_shim_dir = task_tmp / "docker-shim"
        docker_shim_dir.mkdir(mode=0o700)
        docker_shim = ci_validation.write_docker_owner_shim(docker_shim_dir)
        owner_registry = task_tmp / "docker-resource-claims.jsonl"
        descriptor = os.open(owner_registry, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as output:
            for claim in claims:
                output.write(json.dumps(claim, sort_keys=True, separators=(",", ":")) + "\n")
        owner_events = task_tmp / "docker-resource-events.jsonl"
        env = {**os.environ, "COMPOSE_PROJECT_NAME": project, "ELECTRON_CASH_IMAGE": ec_image,
               "TOR_IMAGE": tor_image, "ECD_WALLET_VOLUME": wallet, "ECD_TOR_VOLUME": tor_volume,
                "NETWORK": "chipnet", "USE_TOR": "true", "CASHFUSION_ENABLED": "true",
                "BASIC_AUTH_PASSWORD": uuid.uuid4().hex,
                "WALLET_AUTO_CREATE": "false", "TEST_WALLET_PASSWORD": "", "JSONRPC_ENABLED": "false",
                "JSONRPC_USER": "platform-test", "JSONRPC_PASSWORD": "",
                "ELECTRONCASH_ARGS": "",
                "CI_RESOURCE_OWNER": owner_token, "ECD_TEST_RESOURCE_OWNER": owner_token,
                "CI_DOCKER_OWNER_SHIM": "1", "CI_REAL_DOCKER": shutil.which("docker") or "",
                "CI_RESOURCE_REGISTRY": str(owner_registry), "CI_RESOURCE_EVENT_LOG": str(owner_events),
                 "CI_TASK_BUILDER_RECORD": str(builder_record), "ECD_REPOSITORY_ROOT": str(ROOT),
                 "BUILDX_BUILDER": builder, "CI_PRUNE_TASK_BUILDER": builder,
                 "CI_DISK_FLOOR_BYTES": str(ci_validation.DISK_FLOOR_BYTES),
                 "CI_DISK_CANCEL_BYTES": str(ci_validation.DISK_CANCEL_TRIGGER_BYTES),
                 "CI_DISK_START_BYTES": str(ci_validation.DISK_PHASE_ADMISSIONS_BYTES["builder_bootstrap"]),
                 "ECD_PLATFORM_IMAGE_BUILD_DONE": "1",
                  "ECD_PLATFORM_OVERRIDE": str(platform_override)}
        env.update({name: pins[name] for name in
                    ("EC_VERSION", "EC_COMMIT", "EC_ARCHIVE_SHA256", "TOR_VERSION", "TOR_SOURCE_SHA256")})
        for name, value in approved.items():
            if name.startswith("CASHFUSION_"):
                env[name] = value
        for name in ("COMPOSE_FILE", "COMPOSE_PROFILES", "COMPOSE_PATH_SEPARATOR"):
            env.pop(name, None)
        env["XAUTHORITY"] = str(authority)
        env["PATH"] = str(docker_shim.parent) + os.pathsep + env.get("PATH", "")
        if scope != "mac-xquartz":
            env["DISPLAY"] = container_display
        if relay is not None:
            env["X11_SOCKET_DIR"] = str(socket_dir)
        if scope == "ledger-linux":
            env["HW_USB_GID"] = environment_info["usb_group"]
        compose = compose_args(scope, project, env_file, platform_override)
        if scope == "mac-xquartz":
            # mac-gui.sh consumes the local .env and the same exported isolated image/volume names.
            build_prefix = ["docker", "compose", "--project-directory", str(ROOT), "--env-file", str(ENV_LOCAL),
                            "-p", project, "-f", str(ROOT / "docker-compose.yml"),
                            "-f", str(platform_override)]
        else:
            build_prefix = compose

        image_refs, reusable_images = prepare_platform_images(
            scope, compose, platform_override, image_platforms, env, owner_token, claims, owner_registry)
        ec_image = image_refs["electron-cash"]
        tor_image = image_refs["tor-proxy"]

        def admit_platform_phase(stage: str, required_free_bytes: int) -> int:
            free_before = ci_validation.require_disk_floor(stage)
            if free_before >= required_free_bytes:
                return free_before

            # Only reclaim cache in this run's isolated, durably owned builder,
            # and only after the next phase fails its measured admission check.
            ci_validation.refresh_task_builder_record(builder_record, builder)
            cache_result = ci_validation.checked(
                ["docker", "buildx", "du", "--builder", builder, "--format", "json"], env=env, timeout=240)
            before_items = [json.loads(line) for line in cache_result.stdout.splitlines() if line.strip()]
            if not before_items:
                return ci_validation.require_build_capacity(
                    stage, None, minimum_free_bytes=required_free_bytes)
            prune_command = ["docker", "buildx", "prune", "--builder", builder, "--all", "--force"]
            ci_validation.checked(prune_command, env=env, timeout=300)
            after_result = ci_validation.checked(
                ["docker", "buildx", "du", "--builder", builder, "--format", "json"], env=env, timeout=240)
            after_items = [json.loads(line) for line in after_result.stdout.splitlines() if line.strip()]
            free_after = ci_validation.disk_checkpoint(f"after-platform-cache-reclamation:{stage}")
            print(f"[platform] reclaimed task-owned BuildKit cache before {stage}: "
                  f"{len(before_items)} entries -> {len(after_items)} entries")
            if free_after < required_free_bytes:
                raise RunnerError(
                    f"{stage} still requires {required_free_bytes} bytes after task-cache reclamation; "
                    f"observed {free_after} bytes free")
            return free_after

        try:
            if relay is not None:
                relay.start()
            for service_name in ("electron-cash", "tor-proxy"):
                image_ref = image_refs[service_name]
                if service_name in reusable_images:
                    image_ids[service_name] = reusable_images[service_name]
                    continue
                if service_name == "tor-proxy":
                    service_budget = ci_validation.DISK_TOR_ADMISSION_BYTES
                elif scope == "ledger-linux":
                    service_budget = ci_validation.disk_phase_admission(
                        ci_validation.DISK_NORMAL_WALLET_PEAK_BYTES +
                        ci_validation.DISK_HW_WALLET_INCREMENTAL_PEAK_BYTES)
                else:
                    service_budget = ci_validation.DISK_NORMAL_WALLET_ADMISSION_BYTES
                image_claim = next(claim for claim in claims
                                   if claim.get("kind") == "image" and claim.get("name") == image_ref)
                image_claim["build_attempted"] = True
                docker_ownership.record_image_attempt(owner_registry, image_ref, owner_token, None)
                admit_platform_phase(f"real {scope} image {service_name}", service_budget)
                env["CI_DISK_START_BYTES"] = str(service_budget)
                build_command = [*build_prefix, "build", "--pull", service_name]
                ci_validation.checked(build_command, env=env, timeout=1800,
                                      disk_floor_bytes=ci_validation.DISK_FLOOR_BYTES)
                image_id = checked(["docker", "image", "inspect", "--format", "{{.Id}}", image_ref],
                                   env=env).strip()
                image_claim["expected_id"] = image_id
                docker_ownership.record_image_attempt(owner_registry, image_ref, owner_token, image_id)
                image_ids[service_name] = image_id
                actual_platform = checked(["docker", "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}",
                                           image_ref], env=env).strip()
                expected_platform = image_platforms[service_name]
                if actual_platform != expected_platform:
                    raise RunnerError(
                        f"{service_name} image platform {actual_platform} does not match {expected_platform}")
                print(f"[platform] {service_name} image {image_id} ({actual_platform})")
                ci_validation.require_disk_floor(f"after real {scope} image {service_name} build")
            if relay is not None:
                relay.check()
                probe_container_display(ec_image, container_display, authority, socket_dir, owner_token, env)
                print("[platform] authenticated X11 connection passed through the non-root container boundary",
                      flush=True)
            admit_platform_phase("before real platform runtime", ci_validation.DISK_RUNTIME_ADMISSION_BYTES)
            task_builder_state = ci_validation.refresh_task_builder_record(builder_record, builder)
            cleanup_result["task_owned_builder"] = task_builder_state
            release_builder_lock()
            if scope == "ledger-linux":
                device = ledger_probe(ec_image, environment_info["usb_group"], owner_token)
                environment_info.update({"ledger_model": device["model_id"], "firmware": device["firmware"],
                                         "bch_app": device["bch_app"]})
                print(f"[platform] Ledger {device['model_id']} firmware {device['firmware']}; "
                      "read-only BCH public-path integration passed")
            if scope == "mac-xquartz":
                # mac-gui.sh owns reversible XQuartz TCP/cookie setup and cleanup.
                launch = ["bash", str(ROOT / "scripts/mac-gui.sh")]
            else:
                tor_start = [*compose, "up", "-d", "--no-build", "--no-deps", "tor-proxy"]
                checked(tor_start, env=env, timeout=180)
                tor = wait_tor(project)
                launch = [*compose, "up", "--no-build", "--no-deps", "electron-cash"]
            if scope == "mac-xquartz":
                host_display = xquartz_socket_display(os.environ.get("DISPLAY", ":0"))
            else:
                host_display = display
            process = subprocess.Popen(launch, cwd=ROOT, env=env, stdout=None, stderr=None,
                                       start_new_session=True)
            startup_deadline = time.monotonic() + min(timeout, 180)
            container = None
            while time.monotonic() < startup_deadline:
                if relay is not None:
                    relay.check()
                container = container_for(project)
                if container:
                    state = json.loads(checked(["docker", "inspect", container]))[0]["State"]
                    if state["Status"] == "running":
                        break
                    if state["Status"] in ("exited", "dead"):
                        raise RunnerError("Electron Cash exited before the native GUI was observed")
                if process.poll() is not None and process.returncode:
                    raise RunnerError(f"platform launcher exited with status {process.returncode}")
                time.sleep(1)
            if not container:
                raise RunnerError("Electron Cash container did not start")
            tor = container_for(project, "tor-proxy")
            if not tor:
                raise RunnerError("Tor service is absent in the native GUI Compose path")
            tor_deadline = time.monotonic() + 120
            health = None
            while time.monotonic() < tor_deadline:
                if relay is not None:
                    relay.check()
                health = run(["docker", "inspect", "--format", "{{.State.Health.Status}}", tor])
                if health.stdout.strip() == "healthy":
                    break
                time.sleep(1)
            if health is None or health.stdout.strip() != "healthy":
                raise RunnerError("Tor proxy health check failed during native GUI run")
            tor_sock_check(container)
            services = list_services(project)
            expected_services = ["electron-cash", "tor-proxy"]
            if services != expected_services:
                raise RunnerError(f"unexpected GUI project service set: {services}")
            process_deadline = time.monotonic() + min(timeout, 180)
            top = ""
            process_uid = None
            wallet_pid = None
            while time.monotonic() < process_deadline:
                if relay is not None:
                    relay.check()
                top_result = run(["docker", "top", container, "-eo", "uid,pid,args"], timeout=15)
                if top_result.returncode == 0:
                    top = top_result.stdout
                    identity = wallet_process_identity(top)
                    if identity is not None:
                        process_uid, wallet_pid = identity
                        if process_uid != "10001":
                            raise RunnerError(f"Electron Cash GUI process did not run as wallet UID 10001 "
                                              f"(observed UID={process_uid})")
                        break
                if process.poll() is not None and process.returncode:
                    raise RunnerError(f"platform launcher exited with status {process.returncode}")
                state_result = run(["docker", "inspect", container])
                if state_result.returncode:
                    raise RunnerError("Electron Cash container disappeared before its GUI wrapper started")
                state = json.loads(state_result.stdout)[0]["State"]
                if state["Status"] in ("exited", "dead"):
                    raise RunnerError("Electron Cash exited before its GUI wrapper started")
                time.sleep(1)
            if process_uid is None or wallet_pid is None:
                observed = [line.strip() for line in top.splitlines()[1:] if line.strip()]
                raise RunnerError("Electron Cash GUI wrapper did not start before the deadline; "
                                  f"observed processes={observed}")
            inspect = json.loads(checked(["docker", "inspect", container]))[0]
            host_config = inspect["HostConfig"]
            if (host_config.get("PortBindings") or host_config.get("Privileged") or
                    host_config.get("CapAdd")):
                raise RunnerError("native GUI exposed a host port or privileged container")
            devices = host_config.get("Devices") or []
            device_rules = host_config.get("DeviceCgroupRules") or []
            if scope != "ledger-linux" and (devices or device_rules):
                raise RunnerError("ordinary native GUI unexpectedly received USB access")
            if scope == "ledger-linux":
                if (devices != [{"PathOnHost": "/dev/bus/usb", "PathInContainer": "/dev/bus/usb",
                                 "CgroupPermissions": "rwm"}] or device_rules != ["c 189:* rw"]):
                    raise RunnerError("Ledger GUI received broader-than-required USB access")
                if int(environment_info["usb_group"]) not in process_supplementary_groups(wallet_pid):
                    raise RunnerError("Electron Cash GUI process lacks the Ledger node's supplementary group")
            config_path = "/home/electroncash/.electron-cash/chipnet/config"
            config = json.loads(checked(["docker", "exec", "--user", "10001:10001", container,
                "/opt/electroncash-venv/bin/python", "-c", "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))))", config_path]))
            if config.get("proxy") != "socks5:tor-proxy:9050":
                raise RunnerError("native GUI wallet config does not point to the Tor sidecar")
            marker = "/home/electroncash/.electron-cash/chipnet/.platform-real-persistence"
            checked(["docker", "exec", "--user", "10001:10001", container,
                "/opt/electroncash-venv/bin/python", "-c",
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('retained')", marker])
            window = wait_window(host_display, min(timeout, 180), relay)
            if scope == "mac-xquartz":
                checked(["open", "-a", "XQuartz"])
            screenshot = task_tmp / "electron-cash-window.xwd"
            observation = capture_window(host_display, window, os.environ.copy(), screenshot)
            print(f"[platform] Electron Cash rendered {observation['width']}x{observation['height']} "
                  f"on window {observation['window_id']}", flush=True)
            if scope == "mac-xquartz":
                print("Electron Cash has been detected in XQuartz. The application will remain open for "
                      "inspection. Please check whether you can see the window.", flush=True)
            elif environment_info.get("display_transport") == "ssh-x11-forwarding":
                print("[operator action] Electron Cash should appear on the Mac in XQuartz. Confirm it is visible "
                      "and responsive, then close its window normally.", flush=True)
            else:
                print("[operator action] Confirm Electron Cash is visible and responsive on the host desktop; "
                      "click/focus it, then close its window normally.", flush=True)
            while process.poll() is None:
                if relay is not None:
                    relay.check()
                state = json.loads(checked(["docker", "inspect", container]))[0]["State"]
                if state["Status"] in ("exited", "dead"):
                    break
                time.sleep(1)
            if process.poll() is None and scope == "mac-xquartz":
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired as error:
                    raise RunnerError("XQuartz Compose launcher did not exit after the wallet container stopped") from error
            elif process.poll() is None:
                if container_for(project):
                    command_result(["docker", "exec", "--user", "10001:10001", container,
                                    "/bin/bash", "-c", "touch /tmp/electron-cash-shutdown"], check=False)
                signal_launch_group(process, signal.SIGTERM)
                try:
                    process.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    signal_launch_group(process, signal.SIGTERM)
                    try:
                        process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        signal_launch_group(process, signal.SIGKILL)
                        process.wait(timeout=10)
                raise OperatorActionUnavailable(
                    "operator did not inspect/interact with and close the Electron Cash window before timeout")
            return_code = process.wait()
            if return_code:
                raise RunnerError(f"native GUI process ended with exit code {return_code}")
            if scope != "mac-xquartz":
                exited = json.loads(checked(["docker", "inspect", container]))[0]["State"]
                if exited["Status"] != "exited" or exited["ExitCode"] != 0:
                    raise RunnerError(f"GUI did not close cleanly: {exited}")
                verify_platform_wallet_marker(ec_image, wallet, marker, env)
            else:
                persisted = checked([
                    "docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
                    "--mount", f"type=volume,src={wallet},dst=/wallet,readonly",
                    "--entrypoint", "/opt/electroncash-venv/bin/python", ec_image,
                    "-c", "import pathlib;print(pathlib.Path('/wallet/chipnet/.platform-real-persistence').read_text())",
                ])
                if persisted.strip() != "retained":
                    raise RunnerError("XQuartz wallet state did not persist after clean Compose shutdown")
            if scope == "linux-x11":
                negative_display(ec_image, "", None, "native GUI requires a host DISPLAY", env, socket_dir)
                negative_display(ec_image, ":65533", authority, "host X11 display is unavailable", env, socket_dir)
                bad_auth = display_dir / "wrong-authority"
                source_lines = command_result(["xauth", "nlist", display]).stdout.splitlines()
                malformed_records = []
                for line in source_lines:
                    if len(line) < 32:
                        continue
                    malformed_records.append(line[:-32] + "00" * 16)
                if not malformed_records:
                    raise RunnerError("unable to construct isolated wrong-cookie negative control")
                command_result(["xauth", "-f", str(bad_auth), "nmerge", "-"],
                               input_text="\n".join(malformed_records) + "\n")
                bad_auth.chmod(0o644)
                negative_display(ec_image, container_display, bad_auth,
                                 "host X11 display is unavailable", env, socket_dir)
            if scope == "mac-xquartz":
                if (xquartz_process_name() is not None) != environment_info.get("xquartz_running_before"):
                    raise RunnerError("XQuartz running state was not restored")
                before_listener = environment_info.get("nolisten_tcp_before")
                after_listener = command_result(["defaults", "read", "org.xquartz.X11", "nolisten_tcp"], check=False).stdout.strip() or None
                if before_listener != after_listener:
                    raise RunnerError("XQuartz TCP preference was not restored")
                after_access = xhost_access_fingerprint()
                if after_access != environment_info["xhost_access_sha256_before"]:
                    raise RunnerError("XQuartz host authorization changed during the run")
            cleanup_result["status"] = "PASS"
        except OperatorActionUnavailable as error:
            not_run_error = redact_host_text(str(error))
        except KeyboardInterrupt:
            not_run_error = "operator cancelled the platform check"
        except Exception as error:
            result_error = redact_host_text(str(error))
        finally:
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            signal.signal(signal.SIGHUP, signal.SIG_IGN)
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
            if process and process.poll() is None:
                try:
                    signal_launch_group(process, signal.SIGTERM)
                    process.wait(timeout=30)
                except (OSError, subprocess.TimeoutExpired):
                    try:
                        signal_launch_group(process, signal.SIGKILL)
                        process.wait(timeout=10)
                    except OSError:
                        pass
            if scope != "mac-xquartz":
                down = platform_compose_down(scope, project, env_file, platform_override, env)
                compose_down_returncode = down.returncode
                compose_down_output = (down.stdout + down.stderr).strip()
            cleanup_result = cleanup_task_resources(project, owner_token, claims, preexisting_image_ids)
            if relay is not None:
                relay.close()
                relay_socket_removed = not relay.socket_path.exists()
            else:
                relay_socket_removed = True
            if not relay_socket_removed:
                cleanup_result["status"] = "FAIL"
                cleanup_result.setdefault("failures", []).append(
                    "task X11 relay socket could not be removed safely")
            cleanup_result["preexisting_image_ids"] = {"count": len(preexisting_image_ids),
                                                         "sha256": hashlib.sha256(
                                                             "\n".join(sorted(preexisting_image_ids)).encode()).hexdigest()}
            if compose_down_returncode is not None:
                cleanup_result["compose_down_returncode"] = compose_down_returncode
                if compose_down_returncode != 0:
                    cleanup_result["status"] = "FAIL"
                    detail = redact_host_text(compose_down_output[-1200:])
                    failure = "Compose down returned a nonzero status"
                    if detail:
                        failure += f": {detail}"
                    cleanup_result.setdefault("failures", []).append(failure)
            if not lock_released:
                try:
                    cleanup_result["task_owned_builder"] = ci_validation.refresh_task_builder_record(builder_record, builder)
                except Exception as error:
                    cleanup_result["status"] = "FAIL"
                    cleanup_result.setdefault("failures", []).append(
                        "task-owned Buildx state verification failed: " + redact_host_text(str(error)))
                finally:
                    release_builder_lock()
            cleanup_result["disk_free_after_cleanup_bytes"] = ci_validation.disk_checkpoint(
                "after-platform-owned-resource-cleanup")
            if cleanup_result["disk_free_after_cleanup_bytes"] <= ci_validation.DISK_FLOOR_BYTES:
                cleanup_result["status"] = "FAIL"
                cleanup_result.setdefault("failures", []).append(
                    f"free space reached the {ci_validation.DISK_FLOOR_BYTES}-byte hard reserve "
                    "after real-platform cleanup")
            cleanup_display_transport()
            atexit.unregister(cleanup_display_transport)
        return report_platform_result(scope, cleanup_result, not_run_error, result_error,
                                      image_ids, image_platforms)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capability", choices=SCOPES)
    parser.add_argument("--timeout-seconds", type=int, default=600)
    args = parser.parse_args(argv)
    if args.timeout_seconds < 60 or args.timeout_seconds > 3600:
        parser.error("--timeout-seconds must be between 60 and 3600")

    def session_interrupted(signum: int, _frame: Any) -> None:
        signal.signal(signum, signal.SIG_IGN)
        raise OperatorActionUnavailable("SSH session disconnected; owned task resources are being cleaned")

    previous_handlers = {number: signal.signal(number, session_interrupted)
                         for number in (signal.SIGHUP, signal.SIGTERM)}
    try:
        return run_platform(args.capability, args.timeout_seconds)
    except PrerequisiteError as error:
        print(f"NOT RUN platform-run {args.capability}: {error}", file=sys.stderr, flush=True)
        return 2
    except (RunnerError, subprocess.TimeoutExpired, OSError, ValueError) as error:
        print(f"FAIL platform-run {args.capability}: {error}", file=sys.stderr, flush=True)
        return 1
    finally:
        for number, handler in previous_handlers.items():
            signal.signal(number, handler)


if __name__ == "__main__":
    raise SystemExit(main())
