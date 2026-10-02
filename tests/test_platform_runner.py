#!/usr/bin/env python3
"""Fast guards for opt-in platform command dispatch and host prerequisites."""
from __future__ import annotations

import hashlib
import inspect
import io
import json
import os
import plistlib
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import types
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import platform_runner


def synthetic_xauthority_record(display_number: str, cookie: str, address: str = "ssh-host/unix") -> str:
    values = [address.encode(), display_number.encode(), b"MIT-MAGIC-COOKIE-1", bytes.fromhex(cookie)]
    fields = ["0100"]
    for value in values:
        fields.extend((f"{len(value):04x}", value.hex()))
    return " ".join(fields)


def mac_host_case(state: str, cookie: bool, display: str = ":0"):
    with tempfile.TemporaryDirectory(prefix="ecd-mac-preflight-") as temporary:
        app = Path(temporary) / "XQuartz.app"
        info_plist = app / "Contents" / "Info.plist"
        info_plist.parent.mkdir(parents=True)
        info_plist.write_bytes(plistlib.dumps({"CFBundleShortVersionString": "2.8.5"}))
        calls = []

        def checked(command, **_kwargs):
            if command[:3] == ["docker", "context", "inspect"]:
                return '{"Host":"unix:///var/run/docker.sock"}'
            if command[:3] == ["docker", "info", "--format"]:
                return "Docker Desktop"
            if command[:3] == ["docker", "version", "--format"]:
                return "29.8.0"
            if command[:3] == ["docker", "compose", "version"]:
                return "5.5.1"
            raise AssertionError(command)

        def command_result(command, **_kwargs):
            calls.append(command)
            if command[:2] == ["pgrep", "-x"]:
                name = command[2]
                code = (1 if name == "X11" else 0) if state == "running_bin" else {
                    "running": 0, "stopped": 1, "unknown": 2}[state]
                return subprocess.CompletedProcess(command, code, "", "")
            if command[:2] in (["xauth", "list"], ["xauth", "nlist"]):
                present = cookie and command[-1] == ":0"
                output = "xquartz/unix:0 MIT-MAGIC-COOKIE-1 cookie\n" if command[1] == "list" and present \
                    else ("cookie\n" if present else "")
                return subprocess.CompletedProcess(command, 0 if present else 1, output, "")
            if command[:2] == ["defaults", "read"]:
                return subprocess.CompletedProcess(command, 0, "1\n", "")
            if command == ["xhost"]:
                return subprocess.CompletedProcess(command, 1, "", "no display")
            raise AssertionError(command)

        missing_store = Path(temporary) / "missing-platform-store"
        with patch.object(platform_runner.platform, "system", return_value="Darwin"), \
                 patch.object(platform_runner.platform, "mac_ver", return_value=("26.7", "", "arm64")), \
                 patch.object(platform_runner, "require_tools"), \
                 patch.object(platform_runner, "checked", side_effect=checked), \
                 patch.object(platform_runner, "command_result", side_effect=command_result), \
             patch.dict(os.environ, {"DISPLAY": display, "XQUARTZ_APP": str(app),
                                         "ECD_PLATFORM_EVIDENCE_HOME": str(missing_store),
                                         "ECD_PLATFORM_EVIDENCE_KEY_FILE": str(missing_store / "trust.key")},
                            clear=False):
            try:
                result = platform_runner.detect_host("mac-xquartz")
            except platform_runner.PrerequisiteError as error:
                assert not missing_store.exists()
                return None, str(error), calls
            assert not missing_store.exists()
            return result, None, calls


def test_xquartz_stopped_running_and_unknown():
    launchd_display = "/var/run/com.apple.launchd.test/org.xquartz:0"
    assert platform_runner.xquartz_socket_display(launchd_display) == ":0"
    assert platform_runner.xquartz_socket_display(":0") == ":0"
    result, error, calls = mac_host_case("running", True, launchd_display)
    assert error is None and result is not None
    assert result[0]["xquartz_running_before"] is True
    assert result[0]["xauthority_cookie_present_before"] is True
    assert ["xauth", "nlist", ":0"] in calls

    result, error, _calls = mac_host_case("running", False)
    assert result is None and error is not None and "MIT-MAGIC-COOKIE-1" in error

    result, error, _calls = mac_host_case("stopped", False, launchd_display)
    assert error is None and result is not None
    assert result[0]["xquartz_running_before"] is False
    assert result[0]["xauthority_cookie_present_before"] is False

    result, error, _calls = mac_host_case("running_bin", True, launchd_display)
    assert error is None and result is not None and result[0]["xquartz_running_before"] is True

    for cookie in (False, True):
        result, error, calls = mac_host_case("unknown", cookie)
        assert result is None and error is not None
        assert "unable to determine whether XQuartz is running" in error
        assert not any(command[:2] == ["xauth", "nlist"] for command in calls)


def test_no_key_or_freeze_required_for_command_dispatch():
    with tempfile.TemporaryDirectory(prefix="ecd-no-evidence-store-") as temporary:
        missing_home = str(Path(temporary) / "absent-store")
        env = {"ECD_PLATFORM_EVIDENCE_HOME": missing_home,
               "ECD_PLATFORM_EVIDENCE_KEY_FILE": f"{missing_home}/trust.key"}
        with patch.dict(os.environ, env, clear=False), \
             patch.object(platform_runner, "run_platform", return_value=0) as launch:
            assert platform_runner.main(["mac-xquartz"]) == 0
            launch.assert_called_once_with("mac-xquartz", 600)
        assert not (Path(missing_home) / "trust.key").exists()

    implementation = inspect.getsource(platform_runner.run_platform)
    report_implementation = inspect.getsource(platform_runner.report_platform_result)
    assert not any(term in implementation for term in
                   ("load_key", "source_snapshot", "candidate_identity", "platform_evidence",
                    "platform-strict", "./scripts/ci.sh gate"))
    assert not hasattr(platform_runner, "evidence")
    assert "test_platform_evidence.py" not in platform_runner.ci_validation.ACCEPTANCE_TESTS
    assert implementation.index("wait_window(") < implementation.index("return report_platform_result(")
    assert "PASS platform-run" in report_implementation
    assert implementation.index("window = wait_window(") < implementation.index(
        'checked(["open", "-a", "XQuartz"])') < implementation.index("observation = capture_window(")
    assert "inspection_deadline" not in implementation
    assert "while process.poll() is None:" in implementation
    assert "should appear on the Mac in XQuartz" in implementation
    assert "Electron Cash has been detected in XQuartz. The application will remain open for " in implementation
    assert "inspection. Please check whether you can see the window." in implementation


def test_missing_linux_display_fails_prerequisite_check():
    def checked(command, **_kwargs):
        if command[:3] == ["docker", "context", "inspect"]:
            return '{"Host":"unix:///var/run/docker.sock"}'
        if command[:3] == ["docker", "info", "--format"]:
            return "Docker Engine - Community"
        if command[:3] == ["docker", "version", "--format"]:
            return "29.8.0"
        if command[:3] == ["docker", "compose", "version"]:
            return "5.5.1"
        raise AssertionError(command)

    with patch.object(platform_runner.platform, "system", return_value="Linux"), \
         patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "checked", side_effect=checked), \
         patch.dict(os.environ, {"DISPLAY": ""}, clear=False):
        try:
            platform_runner.detect_host("linux-x11")
        except platform_runner.PrerequisiteError as error:
            assert "requires a local or authenticated SSH-forwarded DISPLAY" in str(error)
        else:
            raise AssertionError("Linux X11 preflight accepted a missing display")


def test_forwarded_display_parsing_and_authority_preflight():
    assert platform_runner.x11_relay.parse_forwarded_display("localhost:17.2") == ("localhost", 6017, 2)
    assert platform_runner.x11_relay.parse_forwarded_display("127.0.0.1:43") == ("127.0.0.1", 6043, 0)
    for display in ("", "localhost:bad", "10.0.0.1:10.0", "localhost:70000",
                    "localhost:2.3.4", "localhost:10.256", "localhost:" + "9" * 5000):
        try:
            platform_runner.x11_relay.parse_forwarded_display(display)
        except platform_runner.x11_relay.X11RelayError:
            pass
        else:
            raise AssertionError(f"invalid forwarded DISPLAY was accepted: {display!r}")

    def result(command, **_kwargs):
        if command[0] == "xdpyinfo":
            return subprocess.CompletedProcess(command, 0, "vendor string: XQuartz\nvendor release number: 1\n", "")
        if command[:2] == ["xauth", "nlist"]:
            assert command[-1] == "localhost:10.0"
            return subprocess.CompletedProcess(command, 0,
                synthetic_xauthority_record("10", "00112233445566778899aabbccddeeff",
                                             "ssh-host/unix") + "\n", "")
        if command[:2] == ["ps", "-eo"]:
            raise AssertionError("forwarded Mac display should not be mistaken for a local Xvfb")
        raise AssertionError(command)

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", side_effect=result):
        # xauth canonicalizes localhost:10.0 to the stored host/unix:10 record.
        info = platform_runner.local_x11_info("localhost:10.0")
    assert info["display_transport"] == "ssh-x11-forwarding"
    assert info["x_server"] == "vendor string: XQuartz"
    assert info["display"] == ":10.0"

    def missing_cookie(command, **_kwargs):
        if command[0] == "xdpyinfo":
            return subprocess.CompletedProcess(command, 0, "vendor string: XQuartz\n", "")
        return subprocess.CompletedProcess(command, 1, "", "")

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", side_effect=missing_cookie):
        try:
            platform_runner.local_x11_info("localhost:10.0")
        except platform_runner.PrerequisiteError as error:
            assert "no Xauthority cookie" in str(error)
        else:
            raise AssertionError("forwarded display without authorization was accepted")

    def other_display(command, **_kwargs):
        if command[0] == "xdpyinfo":
            return subprocess.CompletedProcess(command, 0, "vendor string: XQuartz\n", "")
        if command[:2] == ["xauth", "nlist"]:
            return subprocess.CompletedProcess(command, 0,
                synthetic_xauthority_record("11", "00112233445566778899aabbccddeeff") + "\n", "")
        raise AssertionError(command)

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", side_effect=other_display):
        try:
            platform_runner.local_x11_info("localhost:10.0")
        except platform_runner.PrerequisiteError as error:
            assert "different display number" in str(error)
        else:
            raise AssertionError("Xauthority for forwarded display 11 was accepted for display 10")

    def ambiguous_display(command, **_kwargs):
        if command[0] == "xdpyinfo":
            return subprocess.CompletedProcess(command, 0, "vendor string: XQuartz\n", "")
        if command[:2] == ["xauth", "nlist"]:
            records = [synthetic_xauthority_record("10", "00112233445566778899aabbccddeeff", "host-a/unix"),
                       synthetic_xauthority_record("10", "ffeeddccbbaa99887766554433221100", "host-b/unix")]
            return subprocess.CompletedProcess(command, 0, "\n".join(records) + "\n", "")
        raise AssertionError(command)

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", side_effect=ambiguous_display):
        try:
            platform_runner.local_x11_info("localhost:10.0")
        except platform_runner.PrerequisiteError as error:
            assert "ambiguous Xauthority entries" in str(error)
        else:
            raise AssertionError("ambiguous forwarded-display authority was accepted")

    try:
        platform_runner.local_x11_info("localhost:10.bad")
    except platform_runner.PrerequisiteError as error:
        assert "SSH-forwarded loopback display" in str(error)
    else:
        raise AssertionError("malformed SSH DISPLAY was accepted")

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", return_value=subprocess.CompletedProcess(
             ["xdpyinfo"], 1, "", "unable to open display localhost:10.0")):
        try:
            platform_runner.local_x11_info("localhost:10.0")
        except platform_runner.PrerequisiteError as error:
            assert "host X11 display is inaccessible" in str(error)
        else:
            raise AssertionError("inaccessible forwarded endpoint was accepted")


def test_real_xauth_local_unix_record_matches_forwarded_display():
    if shutil.which("xauth") is None:
        return
    with tempfile.TemporaryDirectory(prefix="ecd-xauth-forwarded-") as temporary:
        root = Path(temporary)
        source = root / "source-authority"
        cookie = "00112233445566778899aabbccddeeff"
        added = subprocess.run(["xauth", "-f", str(source), "add", ":10",
                                "MIT-MAGIC-COOKIE-1", cookie], capture_output=True,
                               text=True, check=False, timeout=5)
        assert added.returncode == 0, added.stderr
        source_record = subprocess.run(["xauth", "-f", str(source), "nlist", "localhost:10.0"],
                                       capture_output=True, text=True, check=True, timeout=5).stdout.split()
        assert bytes.fromhex(source_record[6]).decode("ascii") == "MIT-MAGIC-COOKIE-1"
        source_metadata = subprocess.run(["xauth", "-f", str(source), "list"],
                                         capture_output=True, text=True, check=True, timeout=5)
        metadata_fields = source_metadata.stdout.split()
        assert metadata_fields[0].endswith("/unix:10")
        assert metadata_fields[1] == "MIT-MAGIC-COOKIE-1"

        original_command_result = platform_runner.command_result

        def command_result(command, **kwargs):
            if command[0] == "xdpyinfo":
                return subprocess.CompletedProcess(
                    command, 0, "vendor string: XQuartz\nvendor release number: 1\n", "")
            return original_command_result(command, **kwargs)

        with patch.object(platform_runner, "require_tools"), \
             patch.object(platform_runner, "command_result", side_effect=command_result), \
             patch.dict(os.environ, {"XAUTHORITY": str(source)}, clear=False):
            info = platform_runner.local_x11_info("localhost:10.0")
            assert info["display_transport"] == "ssh-x11-forwarding"
            mapped_authorities = []
            for socket_name, expected_number, upstream_display, expected_display in (
                    ("X0", 0, "localhost:10.0", ":0.0"),
                    ("X7", 7, "localhost:10.2", ":7.2")):
                task_directory = root / f"task-{expected_number}"
                task_directory.mkdir(mode=0o700)
                authority, container_display, socket_dir, relay = platform_runner.prepare_platform_display(
                    "linux-x11", upstream_display, {"display_transport": "ssh-x11-forwarding"},
                    task_directory, relay_socket_name=socket_name)
                assert container_display == expected_display
                assert relay is not None and relay.socket_path == socket_dir / socket_name
                assert relay.target_host == "localhost" and relay.target_port == 6010
                assert authority.stat().st_mode & 0o777 == 0o644
                assert task_directory.stat().st_mode & 0o777 == 0o700
                assert socket_dir.stat().st_mode & 0o777 == 0o711
                mapped_authorities.append((authority, relay))

        for number, (authority, relay) in zip((0, 7), mapped_authorities):
            screens = ("", ".0") if number == 0 else ("", ".0", ".2")
            for screen in screens:
                selected = subprocess.run(["xauth", "-f", str(authority), "nlist", f":{number}{screen}"],
                                          capture_output=True, text=True, check=True, timeout=5)
                assert sum(bool(line.strip()) for line in selected.stdout.splitlines()) == 1
                mapped_record = selected.stdout.split()
                assert bytes.fromhex(mapped_record[6]).decode("ascii") == "MIT-MAGIC-COOKIE-1"
                assert mapped_record[8] == source_record[8]
            upstream_number = subprocess.run(["xauth", "-f", str(authority), "nlist", ":10"],
                                             capture_output=True, text=True, check=True, timeout=5)
            assert not upstream_number.stdout.strip(), "upstream display 10 leaked into the container lookup key"
            relay.close()
        invalid_task = root / "task-invalid"
        invalid_task.mkdir(mode=0o700)
        try:
            platform_runner.prepare_platform_display(
                "linux-x11", "localhost:10.0", {"display_transport": "ssh-x11-forwarding"},
                invalid_task, relay_socket_name="X-display")
        except platform_runner.x11_relay.X11RelayError:
            pass
        else:
            raise AssertionError("malformed relay socket name was accepted")
    assert not authority.exists(), "temporary container authority was not cleaned with its task directory"


def test_existing_local_x11_preflight_is_retained():
    def result(command, **_kwargs):
        if command[0] == "xdpyinfo":
            return subprocess.CompletedProcess(command, 0,
                                               "vendor string: X.Org\nvendor release number: 123\n", "")
        if command[:2] == ["ps", "-eo"]:
            return subprocess.CompletedProcess(command, 0, "Xorg :0\n", "")
        if command[:2] == ["xauth", "nlist"]:
            assert command[-1] in (":0", "unix:0")
            return subprocess.CompletedProcess(command, 0,
                synthetic_xauthority_record("0", "ffeeddccbbaa99887766554433221100", "local-host/unix") + "\n", "")
        raise AssertionError(command)

    with patch.object(platform_runner, "require_tools"), \
         patch.object(platform_runner, "command_result", side_effect=result):
        info = platform_runner.local_x11_info(":0")
        unix_info = platform_runner.local_x11_info("unix:0")
    assert info["display_transport"] == "local-x11"
    assert info["display"] == ":0"
    assert unix_info["display_transport"] == "local-x11"
    assert unix_info["display"] == ":0"


def test_task_authority_file_is_scoped_and_cookie_is_not_logged():
    authority_implementation = (inspect.getsource(platform_runner.local_x11_info) +
                                inspect.getsource(platform_runner.make_linux_authority))
    assert '["xhost", "+"]' not in authority_implementation
    with tempfile.TemporaryDirectory(prefix="ecd-xauth-test-") as temporary:
        directory = Path(temporary) / "private"
        directory.mkdir(mode=0o700)
        secret = "00112233445566778899aabbccddeeff"
        authority = None

        def result(command, **_kwargs):
            if command[:2] == ["xauth", "nlist"]:
                return subprocess.CompletedProcess(command, 0,
                    synthetic_xauthority_record("10", secret) + "\n", "")
            if command[:4] == ["xauth", "-f", str(directory / "authority"), "nmerge"]:
                assert secret in _kwargs["input_text"]
                assert _kwargs["input_text"].split()[0] == "ffff"
                (directory / "authority").write_text("session cookie record\n", encoding="utf-8")
                return subprocess.CompletedProcess(command, 0, "", "")
            raise AssertionError(command)

        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(platform_runner, "command_result", side_effect=result), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            authority = platform_runner.make_linux_authority("localhost:10.0", directory)
        assert authority.stat().st_mode & 0o777 == 0o644
        assert secret not in stdout.getvalue() + stderr.getvalue()
        assert not directory.is_symlink()
    assert authority is not None and not authority.exists(), "task-scoped authority directory was not removed"


def test_forwarded_x11_relay_uses_private_unix_socket_and_cleans_up():
    with tempfile.TemporaryDirectory(prefix="ecd-x11-relay-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        socket_dir = root / "sockets"
        socket_dir.mkdir(mode=0o711)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def echo_once():
            connection, _ = listener.accept()
            with connection:
                payload = b""
                while not payload.endswith(b"\n"):
                    payload += connection.recv(1024)
                connection.sendall(b"X11:" + payload)

        server = threading.Thread(target=echo_once, daemon=True)
        server.start()
        relay = platform_runner.x11_relay.ForwardedX11Relay(socket_dir / "X0", "127.0.0.1", port)
        relay.start()
        try:
            assert socket_dir.stat().st_mode & 0o777 == 0o711
            assert relay.socket_path.stat().st_mode & 0o777 == 0o666
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                client.connect(str(relay.socket_path))
                client.sendall(b"authenticated-probe\n")
                client.shutdown(socket.SHUT_WR)
                assert client.recv(1024) == b"X11:authenticated-probe\n"
            relay.check()
        finally:
            relay.close()
            listener.close()
            server.join(timeout=2)
        assert not relay.socket_path.exists()


def test_container_x11_probe_keeps_nonroot_and_no_network_boundary():
    with tempfile.TemporaryDirectory(prefix="ecd-x11-probe-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        socket_dir = root / "sockets"
        socket_dir.mkdir(mode=0o711)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        relay = platform_runner.x11_relay.ForwardedX11Relay(
            socket_dir / "X0", "127.0.0.1", listener.getsockname()[1])
        relay.start()
        authority = root / "authority"
        authority.write_text("task-only Xauthority data", encoding="utf-8")
        authority.chmod(0o644)
        try:
            with patch.object(platform_runner, "checked", return_value="") as docker_run:
                platform_runner.probe_container_display(
                    "test-image", ":0", authority, socket_dir, "owner-token", {})
            command = docker_run.call_args.args[0]
            assert "--network" in command and command[command.index("--network") + 1] == "none"
            assert "--user" in command and command[command.index("--user") + 1] == "10001:10001"
            assert "--cap-drop=ALL" in command and "no-new-privileges:true" in command
            assert any(str(socket_dir) in item for item in command)
            assert any(str(authority) in item for item in command)

            try:
                platform_runner.probe_container_display(
                    "test-image", ":1", authority, socket_dir, "owner-token", {})
            except platform_runner.RunnerError as error:
                assert "socket ownership or permissions" in str(error)
            else:
                raise AssertionError("container DISPLAY/relay socket mismatch was accepted")

            authority.chmod(0o600)
            try:
                platform_runner.probe_container_display(
                    "test-image", ":0", authority, socket_dir, "owner-token", {})
            except platform_runner.RunnerError as error:
                assert "Xauthority file" in str(error)
            else:
                raise AssertionError("non-readable task Xauthority was accepted")
        finally:
            relay.close()
            listener.close()


def test_platform_image_tags_follow_resolved_recipe_and_reuse_matching_images():
    with tempfile.TemporaryDirectory(prefix="ecd-platform-image-cache-") as temporary:
        root = Path(temporary)
        owner_registry = root / "claims.jsonl"
        owner_registry.write_text("", encoding="utf-8")
        env = {"ELECTRON_CASH_IMAGE": "pending-wallet", "TOR_IMAGE": "pending-tor"}
        claims = []
        models = [
            {"configuration_sha256": "a" * 64},
            {"configuration_sha256": "b" * 64},
        ]
        image_results = [
            subprocess.CompletedProcess([], 0, json.dumps([{"Id": "sha256:wallet", "Os": "linux",
                                                              "Architecture": "amd64"}]), ""),
            subprocess.CompletedProcess([], 0, json.dumps([{"Id": "sha256:tor", "Os": "linux",
                                                              "Architecture": "amd64"}]), ""),
        ]
        with patch.object(platform_runner, "checked", return_value="{}"), \
             patch.object(platform_runner.ci_validation, "image_build_configuration",
                          side_effect=models), \
             patch.object(platform_runner, "run", side_effect=image_results) as inspect:
            refs, reusable = platform_runner.prepare_platform_images(
                "linux-x11", ["docker", "compose"], root / "platform.yml",
                {"electron-cash": "linux/amd64", "tor-proxy": "linux/amd64"},
                env, "owner-token", claims, owner_registry)

        assert refs == {"electron-cash": "electron-cash-platform:" + "a" * 32,
                        "tor-proxy": "bchforge/electron-cash-docker-tor-platform:" + "b" * 32}
        assert reusable == {"electron-cash": "sha256:wallet", "tor-proxy": "sha256:tor"}
        assert env["ELECTRON_CASH_IMAGE"] == refs["electron-cash"]
        assert env["TOR_IMAGE"] == refs["tor-proxy"]
        assert claims == [] and owner_registry.read_text(encoding="utf-8") == ""
        assert inspect.call_count == 2


def test_virtualhere_stays_out_of_product_services():
    for name in ("docker-compose.yml", "docker-compose.gui.yml", "docker-compose.hw.yml",
                 "docker-compose.headless.yml", "docker-compose.rpc.yml"):
        content = (ROOT / name).read_text(encoding="utf-8").lower()
        assert "virtualhere" not in content, name


def test_ssh_display_override_keeps_its_read_only_authority_contract():
    with tempfile.TemporaryDirectory(prefix="ecd-platform-display-override-") as temporary:
        root = Path(temporary)
        override = root / "platform.yml"
        authority = root / "authority file"
        authority.write_bytes(b"synthetic host authority")
        socket_dir = root / "relay sockets"
        socket_dir.mkdir()
        platform_runner.write_platform_override("linux-x11", override)
        platform_runner.write_platform_display_override(override, authority, socket_dir)
        env = {**os.environ, "BASIC_AUTH_PASSWORD": "synthetic-platform-config",
               "DISPLAY": ":7.0", "XAUTHORITY": str(authority), "HW_USB_GID": "10001"}
        result = subprocess.run(
            ["docker", "compose", "--env-file", str(ROOT / ".env.example"),
             "-p", "ecd-platform-display-config", "-f", str(ROOT / "docker-compose.yml"),
             "-f", str(ROOT / "docker-compose.gui.yml"), "-f", str(override),
             "config", "--format", "json"],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=60)
        assert result.returncode == 0, "Linux/SSH display override did not resolve"
        wallet = json.loads(result.stdout)["services"]["electron-cash"]
        assert wallet["environment"]["XAUTHORITY"] == "/home/electroncash/.Xauthority"
        assert [item["source"] for item in wallet["volumes"]] == [
            "electron-cash-data", str(authority), str(socket_dir)]
        assert all(item.get("read_only") for item in wallet["volumes"][1:])
        assert all(item.get("target") != "/run/ecd-x11" for item in wallet["volumes"])


def test_negative_display_uses_explicit_image_after_gui_exit():
    image = "electron-cash-platform:test-image"
    with tempfile.TemporaryDirectory(prefix="ecd-negative-x11-") as temporary, \
         patch.object(platform_runner, "run", return_value=subprocess.CompletedProcess(
             [], 1, "host X11 display is unavailable", "")) as docker_run, \
         patch.dict(os.environ, {}, clear=True):
        platform_runner.negative_display(
            image, ":65533", None, "host X11 display is unavailable", {}, Path(temporary) / "no-sockets")
        command = docker_run.call_args.args[0]
        assert command[-1] == image
        assert 'os.environ["ELECTRON_CASH_IMAGE"]' not in inspect.getsource(platform_runner.negative_display)


def test_ledger_probe_uses_production_client_shape_and_discards_public_data():
    secret_address = "synthetic-ledger-address-never-log"
    secret_key = "synthetic-public-key-never-log"
    secret_chain = "synthetic-chain-code-never-log"

    def execute_probe(*, include_supported=True, fail_public=False):
        events = []

        class FakeRawHIDDongle:
            closed = False

            def close(self):
                self.closed = True
                events.append("raw-close")

        class FakeBtchipBackend:
            def __init__(self, raw):
                self.dongle = raw

            def getFirmwareVersion(self):
                events.append("firmware")
                return {"version": "2.4.3"}

            def getWalletPublicKey(self, path, showOnScreen=False):
                events.append(("public-path", path, showOnScreen))
                if fail_public:
                    raise RuntimeError("synthetic HID communication failure")
                return {"publicKey": [1] * 65, "address": secret_address,
                        "chainCode": [2] * 32}

        class FakeLedgerClient:
            def __init__(self, plugin, raw, is_hw1):
                assert isinstance(raw, FakeRawHIDDongle)
                self.dongleObject = FakeBtchipBackend(raw)
                self.is_hw1 = is_hw1
                events.append("wrapped-raw-hid")

            def checkDevice(self):
                events.append("production-preflight")

            def supports_bitcoin_cash(self):
                return True

            def close(self):
                self.dongleObject.dongle.close()

        class FakeLedgerPlugin:
            DEVICE_IDS = {(0x2c97, 0x4011)}

            def get_btchip_device(self, info):
                events.append(("raw-hid-open", info.path))
                return FakeRawHIDDongle()

            def create_client(self, info, handler):
                self.handler = handler
                raw = self.get_btchip_device(info)
                return FakeLedgerClient(self, raw, info.product_key[0] == 0x2581)

        plugin_module = types.ModuleType("electroncash_plugins.ledger.ledger")
        setattr(plugin_module, "LedgerPlugin", FakeLedgerPlugin)
        ledger_package = types.ModuleType("electroncash_plugins.ledger")
        ledger_package.__path__ = []
        root_package = types.ModuleType("electroncash_plugins")
        root_package.__path__ = []
        hid_module = types.ModuleType("hid")
        setattr(hid_module, "enumerate", lambda: ([{"vendor_id": 0x2c97, "product_id": 0x4011,
                                                      "interface_number": 0, "usage_page": 0xffa0,
                                                      "path": b"physical-device-path"}]
                                                     if include_supported else []))
        modules = {"hid": hid_module,
                   "electroncash_plugins": root_package,
                   "electroncash_plugins.ledger": ledger_package,
                   "electroncash_plugins.ledger.ledger": plugin_module}
        stdout, stderr = io.StringIO(), io.StringIO()
        result_code = None
        error = None
        with patch.dict(sys.modules, modules), redirect_stdout(stdout), redirect_stderr(stderr):
            try:
                exec(compile(platform_runner.ledger_probe_script(), "<ledger-probe-test>", "exec"), {})
            except SystemExit as exit_result:
                result_code = exit_result.code
            except Exception as caught:
                error = caught
        return events, stdout.getvalue(), stderr.getvalue(), result_code, error

    events, stdout, stderr, result_code, error = execute_probe()
    assert error is None and result_code == 0, repr(error)
    assert "wrapped-raw-hid" in events and "production-preflight" in events
    assert ("public-path", "44'/145'/0'", False) in events
    assert events.count("raw-close") == 1
    result = json.loads(stdout)
    assert result["model_id"] == "2c97:4011"
    assert result["firmware"] == "2.4.3" and result["bch_app"] == "compatible"
    assert result["read_only_bch_path"] == "passed"
    assert all(secret not in stdout + stderr for secret in (secret_address, secret_key, secret_chain))

    events, stdout, stderr, result_code, error = execute_probe(fail_public=True)
    assert isinstance(error, RuntimeError) and "synthetic HID communication failure" in str(error)
    assert events.count("raw-close") == 1
    assert all(secret not in stdout + stderr for secret in (secret_address, secret_key, secret_chain))

    events, stdout, stderr, result_code, error = execute_probe(include_supported=False)
    assert result_code == "no supported Ledger HID device found"
    assert not any(event == "wrapped-raw-hid" for event in events)
    assert "model_id" not in stdout and "Ledger" not in stdout


def test_linux_runner_launches_one_interactive_gui_and_keeps_automated_restart_coverage():
    runner_source = inspect.getsource(platform_runner.run_platform)
    assert runner_source.count("subprocess.Popen(launch") == 1
    assert "restart_command" not in runner_source
    assert "verify_platform_wallet_marker(ec_image, wallet, marker, env)" in runner_source
    assert "write_platform_display_override(platform_override, authority, socket_dir)" in runner_source
    xvfb_source = (ROOT / "tests/test_linux_gui.py").read_text(encoding="utf-8")
    assert 'repeat = run([*project_command, "up", "-d", "electron-cash"]' in xvfb_source
    assert ".x11-compose-persistence" in xvfb_source and "read_text()=='retained'" in xvfb_source


def test_successful_close_and_cleanup_report_zero_after_cleanup():
    output = io.StringIO()
    with redirect_stdout(output):
        status = platform_runner.report_platform_result(
            "linux-x11", {"status": "PASS", "failures": []}, None, None,
            {"electron-cash": "sha256:wallet", "tor-proxy": "sha256:tor"},
            {"electron-cash": "linux/amd64", "tor-proxy": "linux/amd64"})
    assert status == 0
    assert "PASS platform-run linux-x11" in output.getvalue()

    with redirect_stdout(io.StringIO()):
        try:
            platform_runner.report_platform_result(
                "linux-x11", {"status": "PASS", "failures": []}, None, None,
                {"electron-cash": "sha256:wallet"}, {})
        except KeyError as error:
            assert error.args == ("electron-cash",)
        else:
            raise AssertionError("missing final image-platform metadata was silently accepted")

    source = inspect.getsource(platform_runner.run_platform)
    assert source.rindex("cleanup_display_transport()") < source.index("return report_platform_result(")


def test_forwarded_x11_disconnect_is_detected_and_foreign_path_is_retained():
    with tempfile.TemporaryDirectory(prefix="ecd-x11-disconnect-") as temporary:
        root = Path(temporary)
        root.chmod(0o700)
        socket_dir = root / "sockets"
        socket_dir.mkdir(mode=0o711)
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        relay = platform_runner.x11_relay.ForwardedX11Relay(socket_dir / "X0", "127.0.0.1", port)
        relay.start()
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(str(relay.socket_path))
        remote, _ = listener.accept()
        remote.close()
        try:
            deadline = time.monotonic() + 2
            while time.monotonic() < deadline:
                if relay._failed.is_set():
                    break
                time.sleep(0.01)
            try:
                relay.check()
            except platform_runner.x11_relay.X11RelayError as error:
                assert "disconnected" in str(error)
                assert "cookie" not in str(error).lower()
            else:
                raise AssertionError("SSH X11 upstream disconnect was not detected")
            relay.socket_path.unlink()
            relay.socket_path.write_text("foreign file", encoding="utf-8")
        finally:
            client.close()
            listener.close()
            relay.close()
        assert relay.socket_path.read_text(encoding="utf-8") == "foreign file"


def test_no_visible_window_means_no_success():
    with patch.object(platform_runner, "command_result",
                      return_value=subprocess.CompletedProcess(["xwininfo"], 0, "root tree without target", "")), \
         patch.object(platform_runner.time, "monotonic", side_effect=[0.0, 0.0, 2.0]), \
         patch.object(platform_runner.time, "sleep"):
        try:
            platform_runner.wait_window(":0", 1)
        except platform_runner.RunnerError as error:
            assert "Electron Cash window was not observed" in str(error)
        else:
            raise AssertionError("GUI check passed without an observed Electron Cash window")


def test_xwd_header_detects_file_byteorder():
    fields = [0] * 25
    fields[0] = 100
    fields[1] = 7
    fields[4] = 640
    fields[5] = 480
    for byteorder in (">", "<"):
        raw_header = struct.pack(byteorder + "25I", *fields)
        assert platform_runner.unpack_xwd_header(raw_header) == tuple(fields)


def test_unavailable_xhost_state_is_compared_consistently():
    with patch.object(platform_runner, "command_result",
                      return_value=subprocess.CompletedProcess(["xhost"], 1, "", "no display")):
        assert platform_runner.xhost_access_fingerprint() == "unavailable"
    with patch.object(platform_runner, "command_result",
                      return_value=subprocess.CompletedProcess(["xhost"], 0, "access control enabled\n", "")):
        assert platform_runner.xhost_access_fingerprint() == hashlib.sha256(
            b"access control enabled\n").hexdigest()


def test_launcher_signals_only_its_isolated_process_group():
    process = Mock()
    process.pid = 43210
    with patch.object(platform_runner.os, "killpg") as kill_group:
        platform_runner.signal_launch_group(process, platform_runner.signal.SIGTERM)
    kill_group.assert_called_once_with(43210, platform_runner.signal.SIGTERM)
    source = inspect.getsource(platform_runner.run_platform)
    assert "start_new_session=True" in source
    assert "signal_launch_group(process, signal.SIGTERM)" in source
    assert "signal.signal(signal.SIGINT, signal.SIG_IGN)" in source
    main_source = inspect.getsource(platform_runner.main)
    assert "signal.SIGHUP" in main_source and "signal.SIGTERM" in main_source
    assert "SSH session disconnected" in main_source


def test_wallet_process_uid_uses_numeric_uid_column():
    process_table = "UID PID ARGS\n10001 42 /opt/electroncash-venv/bin/python /home/electroncash/electroncash-wrapper.py\n"
    assert platform_runner.wallet_process_uid(process_table) == "10001"
    assert platform_runner.wallet_process_identity(process_table) == ("10001", "42")
    named_user_table = process_table.replace("10001 42", "electroncash 42")
    assert platform_runner.wallet_process_uid(named_user_table) == "electroncash"
    entrypoint_table = "UID PID ARGS\n0 42 /bin/bash /home/electroncash/entrypoint.sh\n"
    assert platform_runner.wallet_process_uid(entrypoint_table) is None
    assert "uid,pid,args" in inspect.getsource(platform_runner.run_platform)
    assert "process_deadline" in inspect.getsource(platform_runner.run_platform)


def test_hw_group_check_uses_the_runtime_setpriv_groups():
    status = "Name:\telectroncash-wrapper\nUid:\t10001\t10001\t10001\t10001\nGid:\t10001\t10001\t10001\t10001\nGroups:\t0 10001\n"
    assert platform_runner.supplementary_groups_from_status(status) == {0, 10001}
    source = inspect.getsource(platform_runner.run_platform)
    assert "process_supplementary_groups(wallet_pid)" in source
    assert 'host_config.get("GroupAdd"' not in source
    entrypoint = (ROOT / "docker/entrypoint.sh").read_text(encoding="utf-8")
    assert 'runtime_groups=(--groups "${HW_USB_GID' in entrypoint
    assert "--reuid 10001 --regid 10001 \"${runtime_groups[@]}\"" in entrypoint


def test_runtime_cleanup_keeps_claimed_images():
    owner = "run-" + "a" * 32
    project = "ecd-real-mac-xquartz-" + "b" * 32
    claims = [
        {"kind": "project", "name": project, "owner_token": owner, "preflight": "ABSENT"},
        {"kind": "volume", "name": project + "-wallet", "owner_token": owner, "preflight": "ABSENT"},
        {"kind": "image", "name": "electron-cash-platform:mac-xquartz", "owner_token": owner,
         "preflight": "ABSENT", "build_attempted": True, "expected_id": "sha256:wallet"},
    ]
    selected = platform_runner.runtime_cleanup_targets(
        owner, claims,
        containers=[{"id": "task-container", "labels": {
            platform_runner.docker_ownership.PROJECT_LABEL: project}}],
        networks=[{"id": "task-network", "labels": {
            platform_runner.docker_ownership.PROJECT_LABEL: project}}],
        volumes=[{"name": project + "-wallet", "labels": {
            platform_runner.docker_ownership.OWNER_LABEL: owner}}],
    )
    assert selected == {"containers": ["task-container"], "networks": ["task-network"],
                        "volumes": [project + "-wallet"], "images": []}


def test_compose_down_reuses_task_environment_before_owned_cleanup():
    with tempfile.TemporaryDirectory(prefix="ecd-compose-down-") as temporary:
        override = Path(temporary) / "image-platform.yml"
        override.write_text("services: {}\n", encoding="utf-8")
        env = {"BASIC_AUTH_PASSWORD": "synthetic-cleanup-only", "DISPLAY": ":3.1",
               "XAUTHORITY": "/tmp/task-authority", "X11_SOCKET_DIR": "/tmp/task-sockets",
               "ELECTRON_CASH_IMAGE": "electron-cash-platform:task-image",
               "TOR_IMAGE": "bchforge/electron-cash-docker-tor-platform:task-image",
               "COMPOSE_PROJECT_NAME": "ecd-task-project",
               "ECD_WALLET_VOLUME": "ecd-task-wallet", "ECD_TOR_VOLUME": "ecd-task-tor"}
        observed = {}

        def command_result(command, **kwargs):
            assert override.is_file(), "Compose override was removed before project down"
            observed["command"] = command
            observed["env"] = kwargs["env"]
            assert kwargs["check"] is False and kwargs["timeout"] == 120
            return subprocess.CompletedProcess(command, 0, "", "")

        with patch.object(platform_runner, "command_result", side_effect=command_result):
            result = platform_runner.platform_compose_down(
                "linux-x11", "ecd-task-project", ROOT / ".env.example", override, env)

        assert result.returncode == 0
        assert observed["command"][-3:] == ["down", "--volumes", "--remove-orphans"]
        assert str(override) in observed["command"]
        assert observed["env"] is env
        assert observed["env"]["BASIC_AUTH_PASSWORD"] == "synthetic-cleanup-only"
        assert observed["env"]["ELECTRON_CASH_IMAGE"] == "electron-cash-platform:task-image"
        assert observed["env"]["TOR_IMAGE"] == "bchforge/electron-cash-docker-tor-platform:task-image"
        assert observed["env"]["ECD_WALLET_VOLUME"] == "ecd-task-wallet"
        cleanup_source = inspect.getsource(platform_runner.run_platform)
        cleanup_source = cleanup_source[cleanup_source.index("if process and process.poll() is None:"):]
        assert cleanup_source.index("platform_compose_down(") < cleanup_source.index(
            "cleanup_task_resources(") < cleanup_source.index("relay.close()") < cleanup_source.index(
            "cleanup_display_transport()")
        assert "if compose_down_returncode != 0:" in cleanup_source
        assert "Compose down returned a nonzero status" in cleanup_source
        assert "down.stdout + down.stderr" in inspect.getsource(platform_runner.run_platform)


def test_platform_targets_and_index_read_only():
    index_text = subprocess.run(["git", "rev-parse", "--git-path", "index"], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
    index_path = Path(index_text)
    if not index_path.is_absolute():
        index_path = ROOT / index_path
    before = hashlib.sha256(index_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ecd-platform-target-") as temporary:
        platform_runner.ci_validation.candidate_identity(Path(temporary))
        for scope in platform_runner.SCOPES:
            override, image_platform = platform_runner.write_platform_override(
                scope, Path(temporary) / f"{scope}.json", machine="arm64")
            tor_platform = "linux/arm64" if scope == "mac-xquartz" else "linux/amd64"
            assert image_platform == {"electron-cash": "linux/amd64", "tor-proxy": tor_platform}
            assert json.loads(override.read_text()) == {"services": {
                "electron-cash": {"platform": "linux/amd64"},
                "tor-proxy": {"platform": tor_platform},
            }}
        assert platform_runner.platform_targets("mac-xquartz", "x86_64") == {
            "electron-cash": "linux/amd64", "tor-proxy": "linux/amd64"}
    after = hashlib.sha256(index_path.read_bytes()).hexdigest()
    assert after == before, "platform help/target/preflight tooling modified the user's Git index"


def test_simple_cli_and_retired_certification_commands():
    index_text = subprocess.run(["git", "rev-parse", "--git-path", "index"], cwd=ROOT,
                                capture_output=True, text=True, check=True).stdout.strip()
    index_path = Path(index_text)
    if not index_path.is_absolute():
        index_path = ROOT / index_path
    before = hashlib.sha256(index_path.read_bytes()).hexdigest()
    with tempfile.TemporaryDirectory(prefix="ecd-cli-no-key-") as temporary:
        env = {**os.environ, "XDG_STATE_HOME": temporary}
        help_result = subprocess.run(["bash", str(ROOT / "scripts/ci.sh"), "--help"],
                                     cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
        assert help_result.returncode == 0
        assert "platform-run mac-xquartz" in help_result.stdout
        assert "platform-run linux-x11" in help_result.stdout
        assert "platform-run ledger-linux" in help_result.stdout
        retired = ("evidence-key-init", "evidence-import", "evidence-export", "evidence-targets",
                   "platform-report", "platform-strict")
        for command in retired:
            result = subprocess.run(["bash", str(ROOT / "scripts/ci.sh"), command],
                                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=30)
            assert result.returncode != 0, f"retired command {command} returned success"
            assert "PASS" not in result.stdout + result.stderr
        assert not (Path(temporary) / "electron-cash-docker/platform-evidence/trust.key").exists()
    after = hashlib.sha256(index_path.read_bytes()).hexdigest()
    assert after == before, "CLI help/preflight modified the user's Git index"


def main():
    test_xquartz_stopped_running_and_unknown()
    test_no_key_or_freeze_required_for_command_dispatch()
    test_missing_linux_display_fails_prerequisite_check()
    test_forwarded_display_parsing_and_authority_preflight()
    test_real_xauth_local_unix_record_matches_forwarded_display()
    test_existing_local_x11_preflight_is_retained()
    test_task_authority_file_is_scoped_and_cookie_is_not_logged()
    test_forwarded_x11_relay_uses_private_unix_socket_and_cleans_up()
    test_container_x11_probe_keeps_nonroot_and_no_network_boundary()
    test_platform_image_tags_follow_resolved_recipe_and_reuse_matching_images()
    test_ledger_probe_uses_production_client_shape_and_discards_public_data()
    test_negative_display_uses_explicit_image_after_gui_exit()
    test_linux_runner_launches_one_interactive_gui_and_keeps_automated_restart_coverage()
    test_successful_close_and_cleanup_report_zero_after_cleanup()
    test_forwarded_x11_disconnect_is_detected_and_foreign_path_is_retained()
    test_virtualhere_stays_out_of_product_services()
    test_no_visible_window_means_no_success()
    test_xwd_header_detects_file_byteorder()
    test_unavailable_xhost_state_is_compared_consistently()
    test_launcher_signals_only_its_isolated_process_group()
    test_wallet_process_uid_uses_numeric_uid_column()
    test_hw_group_check_uses_the_runtime_setpriv_groups()
    test_runtime_cleanup_keeps_claimed_images()
    test_compose_down_reuses_task_environment_before_owned_cleanup()
    test_platform_targets_and_index_read_only()
    test_simple_cli_and_retired_certification_commands()
    help_result = subprocess.run([sys.executable, str(ROOT / "scripts/platform_runner.py"), "--help"],
                                 capture_output=True, text=True, timeout=30)
    assert help_result.returncode == 0
    assert all(scope in help_result.stdout for scope in platform_runner.SCOPES)
    print("PASS platform dispatch, prerequisite, XQuartz-state, visible-window, and index guards")


if __name__ == "__main__":
    main()
