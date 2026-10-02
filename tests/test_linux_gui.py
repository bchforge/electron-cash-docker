#!/usr/bin/env python3
"""Authenticated external-Xvfb integration through the production Linux Compose overlay."""

from __future__ import annotations

import json
import hashlib
import importlib.util
import os
import re
import secrets
import signal
import socket
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

from test_support import (
    ROOT,
    electron_cash_image,
    remove_owned_volume,
    tor_image,
    unique_project,
    unique_resource,
)


GUI_FILES = ("docker-compose.yml", "docker-compose.gui.yml")
REMOTE_SERVICES = {"auth-session", "caddy", "fail2ban"}


def run(command: list[str], *, env: dict[str, str] | None = None,
        timeout: int = 120) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True,
                          timeout=timeout, check=False)


def compose(project: str, *, gui: bool = True) -> list[str]:
    command = ["docker", "compose", "--project-directory", str(ROOT),
               "--env-file", str(ROOT / ".env.example"), "-p", project]
    for filename in (GUI_FILES if gui else ("docker-compose.yml",)):
        command += ["-f", str(ROOT / filename)]
    return command


def free_port() -> str:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        listener.bind(("127.0.0.1", 0))
        return str(listener.getsockname()[1])
    finally:
        listener.close()


def choose_display() -> tuple[str, str]:
    socket_dir = Path("/tmp/.X11-unix")
    for number in range(80, 200):
        if not (socket_dir / f"X{number}").exists() and not Path(f"/tmp/.X{number}-lock").exists():
            return f":{number}.0", str(number)
    raise AssertionError("no unused Xvfb display number is available")


def write_host_authority(path: Path, display_number: str, cookie: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    hostname = socket.gethostname().encode("utf-8")
    display = display_number.encode("ascii")
    protocol = b"MIT-MAGIC-COOKIE-1"
    cookie_bytes = bytes.fromhex(cookie)
    fields = (
        f"{256:04x}", f"{len(hostname):04x}", hostname.hex(),
        f"{len(display):04x}", display.hex(), f"{len(protocol):04x}", protocol.hex(),
        f"{len(cookie_bytes):04x}", cookie_bytes.hex(),
    )
    merged = subprocess.run(["xauth", "-f", str(path), "nmerge", "-"],
                            input=" ".join(fields), text=True, capture_output=True, timeout=10)
    assert merged.returncode == 0, "unable to create the private Xvfb session authority"
    path.chmod(0o600)
    info = path.stat()
    assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid != 10001


def check_xauthority_display_normalization() -> None:
    spec = importlib.util.spec_from_file_location(
        "prepare_xauthority_test", ROOT / "docker/prepare-xauthority.py")
    assert spec and spec.loader
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    with tempfile.TemporaryDirectory(prefix="ecd-xauth-display-test-") as temporary:
        root = Path(temporary)
        source_dir = root / "host home"
        source_dir.mkdir(mode=0o700)
        authority = source_dir / ".Xauthority"
        volume = root / "private volume"
        volume.mkdir(mode=0o700)
        setattr(helper, "OUTPUT", volume / "authority")
        write_host_authority(authority, "80", "00112233445566778899aabbccddeeff")
        authority.chmod(0o400)
        source_dir.chmod(0o500)
        try:
            setattr(helper, "DISPLAY", ":80")
            plain_record = helper.matching_records(authority)
            setattr(helper, "DISPLAY", ":80.0")
            screen_record = helper.matching_records(authority)
            assert plain_record and screen_record == plain_record
            assert not list(volume.glob(".authority-source-*")), "temporary read-only source copy leaked"
        finally:
            source_dir.chmod(0o700)
        assert helper.normalize_xauth_display(":80") == helper.normalize_xauth_display(":80.0") == ":80"
        assert helper.normalize_xauth_display("unix:80.2") == "unix:80"

    for malformed in ("", "80", ":80.", ":80.screen", ":80.0.1", ":99"):
        try:
            helper.normalize_xauth_display(malformed)
        except ValueError:
            continue
        raise AssertionError(f"malformed DISPLAY was accepted: {malformed!r}")


def start_xvfb(display: str, authority: Path, framebuffer: Path) -> subprocess.Popen:
    framebuffer.mkdir(mode=0o700, parents=True, exist_ok=True)
    process = subprocess.Popen(
        ["Xvfb", display, "-screen", "0", "1024x768x24", "-nolisten", "tcp",
         "-auth", str(authority), "-fbdir", str(framebuffer)],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    number = display.rsplit(":", 1)[1].split(".", 1)[0]
    path = Path("/tmp/.X11-unix") / f"X{number}"
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        if path.is_socket():
            return process
        if process.poll() is not None:
            break
        time.sleep(0.1)
    process.terminate()
    process.wait(timeout=10)
    raise AssertionError("task-owned external Xvfb did not create its local display socket")


def stop_xvfb(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    process.wait(timeout=10)


def compose_id(command: list[str], service: str, env: dict[str, str], *, all_containers: bool = False) -> str:
    result = run([*command, "ps", *( ["--all"] if all_containers else []), "-q", service], env=env)
    assert result.returncode == 0, "unable to query the task-owned Compose service"
    return result.stdout.strip()


def inspect_health(container: str, env: dict[str, str]) -> str:
    result = run(["docker", "inspect", "--format",
                  "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
                  container], env=env)
    assert result.returncode == 0, "unable to inspect the task-owned container health"
    return result.stdout.strip()


def wait_health(command: list[str], service: str, env: dict[str, str], timeout: int = 100) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        container = compose_id(command, service, env)
        if container and inspect_health(container, env) == "healthy":
            return container
        time.sleep(0.5)
    container = compose_id(command, service, env, all_containers=True)
    if container:
        state = run(["docker", "inspect", "--format", "{{json .State}}", container], env=env)
        logs = run(["docker", "logs", "--tail", "40", container], env=env)
        details = (f"container={container}; state={state.stdout.strip() or state.stderr.strip()}; "
                   f"logs={logs.stdout + logs.stderr}")
        details = re.sub(r"(?i)(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])", "[REDACTED_XAUTH]", details)
    else:
        details = "no task-owned Compose container was found"
    raise AssertionError(f"{service} did not become healthy through the production Compose path: {details}")


def wait_for_window(container: str, display: str, env: dict[str, str], timeout: int = 45) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        probe = run(["docker", "exec", "--user", "10001:10001", container,
                     "xwininfo", "-display", display, "-root", "-tree"], env=env)
        if probe.returncode == 0:
            windows = [line for line in probe.stdout.splitlines() if "Electron Cash" in line]
            if windows:
                assert len(windows) == 1, "more than one Electron Cash GUI window is open"
                return windows[0].split()[0]
        time.sleep(0.5)
    raise AssertionError("the non-root Electron Cash window did not appear on the authenticated Xvfb")


def assert_private_copy(helper: str, wallet: str, display: str, env: dict[str, str]) -> None:
    file_stat = run(["docker", "exec", helper, "stat", "-c", "%u:%g %a", "/run/ecd-x11/authority"], env=env)
    assert file_stat.returncode == 0 and file_stat.stdout.strip() == "10001:10001 400"
    records = run(["docker", "exec", helper, "xauth", "-f", "/run/ecd-x11/authority", "nlist", display], env=env)
    assert records.returncode == 0 and records.stdout.splitlines()
    assert all(record.startswith("ffff ") for record in records.stdout.splitlines())

    helper_info = json.loads(run(["docker", "inspect", helper], env=env).stdout)[0]
    helper_config = helper_info["Config"]
    helper_host = helper_info["HostConfig"]
    assert helper_config["User"] == "0:0" and not helper_host["Privileged"]
    helper_script = next(mount for mount in helper_info["Mounts"]
                         if mount["Destination"] == "/home/electroncash/prepare-xauthority.py")
    assert helper_script["Type"] == "bind" and not helper_script["RW"]
    assert helper_script["Source"] == str(ROOT / "docker/prepare-xauthority.py")
    helper_socket = next(mount for mount in helper_info["Mounts"]
                         if mount["Destination"] == "/tmp/.X11-unix")
    assert helper_socket["Type"] == "bind" and not helper_socket["RW"]
    assert helper_socket["Source"] == "/tmp/.X11-unix"
    caps = {value.removeprefix("CAP_") for value in helper_host["CapAdd"] or []}
    dropped = {value.removeprefix("CAP_") for value in helper_host["CapDrop"] or []}
    assert caps == {"CHOWN", "DAC_READ_SEARCH"}
    assert dropped == {"ALL"}
    assert helper_host["NetworkMode"] == "none"
    source_mount = next(mount for mount in helper_info["Mounts"]
                        if mount["Destination"] == "/run/host-x11-authority")
    assert source_mount["Type"] == "bind" and not source_mount["RW"]

    wallet_info = json.loads(run(["docker", "inspect", wallet], env=env).stdout)[0]
    wallet_env = dict(entry.split("=", 1) for entry in wallet_info["Config"]["Env"] if "=" in entry)
    assert wallet_env.get("XAUTHORITY") == "/run/ecd-x11/authority"
    prepared_mount = next(mount for mount in wallet_info["Mounts"]
                          if mount["Destination"] == "/run/ecd-x11")
    assert prepared_mount["Type"] == "volume" and not prepared_mount["RW"]
    assert all(mount["Destination"] != "/home/electroncash/.Xauthority" for mount in wallet_info["Mounts"])


def assert_no_cookie_output(command: list[str], env: dict[str, str], output: str,
                            cookies: tuple[str, ...]) -> None:
    logs = run([*command, "logs", "--no-color", "x11-authority"], env=env)
    combined = output + logs.stdout + logs.stderr
    for cookie in cookies:
        assert cookie.lower() not in combined.lower(), "an Xauthority cookie appeared in user-visible output"


def start_gui(command: list[str], env: dict[str, str], display: str,
              cookies: tuple[str, ...], *, detach: bool = True):
    args = [*command, "up"] + (["-d"] if detach else [])
    result = run(args, env=env, timeout=240)
    assert result.returncode == 0, "documented Linux GUI Compose command did not start"
    assert "pull access denied" not in (result.stdout + result.stderr).lower()
    assert "Building" not in result.stdout, "a warm candidate image was unexpectedly rebuilt"
    helper = wait_health(command, "x11-authority", env)
    tor = wait_health(command, "tor-proxy", env)
    wallet = compose_id(command, "electron-cash", env)
    assert wallet
    wait_for_window(wallet, display, env)
    assert_private_copy(helper, wallet, display, env)
    active = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={command[command.index('-p') + 1]}",
                  "--format", "{{.Label \"com.docker.compose.service\"}}"], env=env)
    assert active.returncode == 0
    assert set(active.stdout.splitlines()) == {"electron-cash", "tor-proxy", "x11-authority"}
    assert set(active.stdout.splitlines()).isdisjoint(REMOTE_SERVICES)
    processes = run(["docker", "top", wallet, "-eo", "user,pid,args"], env=env)
    assert processes.returncode == 0 and "electroncash-wrapper.py --chipnet" in processes.stdout
    application = next(line for line in processes.stdout.splitlines() if "electroncash-wrapper.py" in line)
    assert application.split()[0] not in {"root", "0"}
    wallet_info = json.loads(run(["docker", "inspect", wallet], env=env).stdout)[0]
    assert not wallet_info["HostConfig"]["Privileged"] and not wallet_info["HostConfig"]["Devices"]
    proxy = run(["docker", "exec", "--user", "10001:10001", wallet,
                 "/opt/electroncash-venv/bin/python", "-c",
                 "import json;print(json.load(open('/home/electroncash/.electron-cash/chipnet/config'))['proxy'])"], env=env)
    assert proxy.returncode == 0 and proxy.stdout.strip() == "socks5:tor-proxy:9050"
    socks = run(["docker", "exec", "--user", "10001:10001", wallet,
                 "/opt/electroncash-venv/bin/python", "-c",
                 "import socket;s=socket.create_connection(('tor-proxy',9050),5);s.sendall(b'\\x05\\x01\\x00');r=s.recv(2);s.close();assert r==b'\\x05\\x00',r"], env=env)
    assert socks.returncode == 0
    assert_no_cookie_output(command, env, result.stdout + result.stderr, cookies)
    return wallet, helper


def assert_no_private_cookie_file(command: list[str], env: dict[str, str], image: str,
                                  volume: str) -> None:
    inspected = run(["docker", "volume", "inspect", volume], env=env)
    assert inspected.returncode == 0, "the task-owned Xauthority volume disappeared unexpectedly"
    code = "from pathlib import Path; raise SystemExit(int(Path('/run/ecd-x11/authority').exists()))"
    checked = run(["docker", "run", "--rm", "--pull=never", "--network", "none", "--read-only",
                   "--cap-drop=ALL", "--user", "10001:10001", "-e", "PYTHONDONTWRITEBYTECODE=1",
                   "--mount", f"type=volume,src={volume},dst=/run/ecd-x11,readonly",
                   "--entrypoint", "/usr/bin/python3", image, "-c", code], env=env)
    assert checked.returncode == 0, "Compose teardown left the copied host Xauthority cookie behind"


def wait_unhealthy(helper: str, env: dict[str, str], timeout: int = 30) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if inspect_health(helper, env) == "unhealthy":
            return helper
        time.sleep(0.5)
    raise AssertionError("the rotated X11 session still appeared healthy with its stale cookie")


def wait_failed_prep(helper: str, env: dict[str, str], timeout: int = 45) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = inspect_health(helper, env)
        if state in {"unhealthy", "exited", "dead"}:
            return state
        time.sleep(0.5)
    raise AssertionError("the invalid authority was not rejected within the bounded helper retry period")


def negative_compose_launch(label: str, env: dict[str, str], display: str,
                            cookies: tuple[str, ...], *, cookie_error: bool = False) -> None:
    project = unique_project("x11-negative-" + label)
    wallet = unique_resource("x11-negative-wallet")
    tor = unique_resource("x11-negative-tor")
    env = {**env, "ECD_WALLET_VOLUME": wallet, "ECD_TOR_VOLUME": tor}
    command = compose(project)
    helper_id = ""
    try:
        result = run([*command, "up", "-d", "electron-cash"], env=env, timeout=120)
        if cookie_error:
            helper_id = compose_id(command, "x11-authority", env, all_containers=True)
            assert helper_id, "the production Xauthority service was not created for the wrong-cookie case"
            assert wait_failed_prep(helper_id, env) in {"unhealthy", "exited", "dead"}
        else:
            assert result.returncode != 0, "Compose accepted a missing DISPLAY prerequisite"
        active = run(["docker", "ps", "-q", "--filter", f"label=com.docker.compose.project={project}",
                      "--filter", "label=com.docker.compose.service=electron-cash"], env=env)
        assert active.returncode == 0 and not active.stdout.strip()
        logs = run([*command, "logs", "--no-color", "x11-authority"], env=env)
        assert_no_cookie_output(command, env, result.stdout + result.stderr + logs.stdout + logs.stderr, cookies)
    finally:
        down = run([*command, "down", "--remove-orphans"], env=env)
        assert down.returncode == 0, "negative X11 scenario cleanup failed"
        for name in (wallet, tor, f"{project}_x11-authority"):
            remove_owned_volume(name)


def main() -> None:
    check_xauthority_display_normalization()
    project = unique_project("v04-x11-compose")
    wallet = unique_resource("v04-x11-wallet")
    tor = unique_resource("v04-x11-tor")
    display, display_number = choose_display()
    project_command = compose(project)
    default_image = electron_cash_image()
    authority_volume = f"{project}_x11-authority"

    with tempfile.TemporaryDirectory(prefix="ecd-v04-x11-compose-") as temporary:
        task_dir = Path(temporary)
        home = task_dir / "desktop home"
        default_authority = home / ".Xauthority"
        custom_authority = task_dir / "custom authority path" / "Xauthority with spaces"
        framebuffer = task_dir / "framebuffer"
        cookie_one = secrets.token_hex(16)
        write_host_authority(default_authority, display_number, cookie_one)
        original_authority_hash = hashlib.sha256(default_authority.read_bytes()).hexdigest()
        server = start_xvfb(display, default_authority, framebuffer)
        environment = {**os.environ, "HOME": str(home), "BASIC_AUTH_PASSWORD": uuid.uuid4().hex,
                       "NETWORK": "chipnet", "DISPLAY": display, "USE_TOR": "true",
                       "ELECTRON_CASH_IMAGE": electron_cash_image(), "TOR_IMAGE": tor_image(),
                       "ECD_WALLET_VOLUME": wallet, "ECD_TOR_VOLUME": tor,
                       "CADDY_HTTP_HOST_PORT": free_port(), "CADDY_HTTPS_HOST_PORT": free_port()}
        environment.pop("COMPOSE_PROFILES", None)
        environment.pop("XAUTHORITY", None)
        attached = None
        try:
            # This is the documented exact overlay command, foreground form;
            # the host file stays 0600 and the Compose service creates the copy.
            log_path = task_dir / "attached-compose.log"
            with log_path.open("w+b") as output:
                attached = subprocess.Popen([*project_command, "up"], cwd=ROOT, env=environment,
                                            stdout=output, stderr=subprocess.STDOUT)
                helper = wait_health(project_command, "x11-authority", environment)
                tor_container = wait_health(project_command, "tor-proxy", environment)
                wallet_container = wait_health(project_command, "electron-cash", environment)
                wait_for_window(wallet_container, display, environment)
                assert_private_copy(helper, wallet_container, display, environment)
                assert inspect_health(tor_container, environment) == "healthy"
                assert default_authority.stat().st_uid != 10001
                assert stat.S_IMODE(default_authority.stat().st_mode) == 0o600
                assert hashlib.sha256(default_authority.read_bytes()).hexdigest() == original_authority_hash

                marker = "/home/electroncash/.electron-cash/chipnet/.x11-compose-persistence"
                write = run(["docker", "exec", "--user", "10001:10001", wallet_container,
                             "/opt/electroncash-venv/bin/python", "-c",
                             "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('retained')", marker],
                            env=environment)
                assert write.returncode == 0

                # The existing one-shot GUI shutdown event follows Qt's close path.
                closed_wallet = run(["docker", "exec", "--user", "10001:10001", wallet_container,
                                     "/bin/bash", "-c", "touch /tmp/electron-cash-shutdown"],
                                    env=environment)
                assert closed_wallet.returncode == 0
                deadline = time.monotonic() + 30
                state = None
                while time.monotonic() < deadline:
                    state = json.loads(run(["docker", "inspect", wallet_container], env=environment).stdout)[0]["State"]
                    if state["Status"] == "exited":
                        break
                    time.sleep(0.25)
                assert state and state["Status"] == "exited" and state["ExitCode"] == 0

                if attached.poll() is None:
                    attached.send_signal(signal.SIGINT)
                attached.wait(timeout=30)
                output.flush()
                output.seek(0)
                attached_log = output.read().decode(errors="replace")
                assert cookie_one.lower() not in attached_log.lower()

            down = run([*project_command, "down", "--remove-orphans"], env=environment)
            assert down.returncode == 0
            assert_no_private_cookie_file(project_command, environment, default_image, authority_volume)

            # A second ordinary start exercises the default HOME/.Xauthority
            # resolution with an already-built image and the same wallet volume.
            wallet_container, helper = start_gui(project_command, environment, display, (cookie_one,))
            assert_private_copy(helper, wallet_container, display, environment)

            # Replace the host authority atomically and restart the task-owned
            # X server with the new cookie. The bind-mounted old inode must not
            # remain falsely healthy; down/up remounts the session's new file.
            cookie_two = secrets.token_hex(16)
            replacement = home / ".Xauthority.next"
            write_host_authority(replacement, display_number, cookie_two)
            stop_xvfb(server)
            server = None
            os.replace(replacement, default_authority)
            rotated_authority_hash = hashlib.sha256(default_authority.read_bytes()).hexdigest()
            server = start_xvfb(display, default_authority, framebuffer)
            wait_unhealthy(helper, environment)
            health_log = run(["docker", "inspect", "--format", "{{json .State.Health.Log}}", helper],
                             env=environment)
            assert health_log.returncode == 0
            assert "no longer accepts the cookie" in health_log.stdout
            assert cookie_one.lower() not in health_log.stdout.lower()
            assert cookie_two.lower() not in health_log.stdout.lower()

            down = run([*project_command, "down", "--remove-orphans"], env=environment)
            assert down.returncode == 0
            assert_no_private_cookie_file(project_command, environment, default_image, authority_volume)

            # Exercise a custom authority location containing spaces after a
            # desktop-cookie rotation; this remounts the host path afresh.
            write_host_authority(custom_authority, display_number, cookie_two)
            environment["XAUTHORITY"] = str(custom_authority)
            custom_authority_hash = hashlib.sha256(custom_authority.read_bytes()).hexdigest()
            wallet_container, helper = start_gui(project_command, environment, display,
                                                  (cookie_one, cookie_two))
            assert_private_copy(helper, wallet_container, display, environment)
            assert hashlib.sha256(custom_authority.read_bytes()).hexdigest() == custom_authority_hash

            # Stop/start and explicit restart preserve the disposable wallet
            # marker and keep exactly one authenticated GUI window.
            stop = run([*project_command, "stop", "electron-cash"], env=environment)
            assert stop.returncode == 0
            repeat = run([*project_command, "up", "-d", "electron-cash"], env=environment, timeout=90)
            assert repeat.returncode == 0
            wallet_container = compose_id(project_command, "electron-cash", environment)
            assert wallet_container
            wait_for_window(wallet_container, display, environment)
            restarted = run([*project_command, "restart", "electron-cash"], env=environment, timeout=90)
            assert restarted.returncode == 0
            wait_for_window(wallet_container, display, environment)

            # Mode switching uses the same project and named wallet volume.
            down = run([*project_command, "down", "--remove-orphans"], env=environment)
            assert down.returncode == 0
            assert_no_private_cookie_file(project_command, environment, default_image, authority_volume)
            browser = compose(project, gui=False)
            browser_start = run([*browser, "up", "-d"], env=environment, timeout=180)
            assert browser_start.returncode == 0
            browser_services = run(["docker", "ps", "--filter", f"label=com.docker.compose.project={project}",
                                    "--format", "{{.Label \"com.docker.compose.service\"}}"], env=environment)
            assert browser_services.returncode == 0
            assert set(browser_services.stdout.splitlines()) == {
                "electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"}
            preserved = run(["docker", "exec", "--user", "10001:10001", compose_id(browser, "electron-cash", environment),
                             "/opt/electroncash-venv/bin/python", "-c",
                             "import pathlib,sys;assert pathlib.Path(sys.argv[1]).read_text()=='retained'", marker],
                            env=environment)
            assert preserved.returncode == 0, "GUI-to-browser mode switch lost persistent wallet state"
            browser_down = run([*browser, "down", "--remove-orphans"], env=environment)
            assert browser_down.returncode == 0

            # Missing display is rejected during Compose interpolation, before
            # any container is created. Missing authority/socket and a wrong
            # cookie go through the same production helper service.
            no_display = environment.copy()
            no_display.pop("DISPLAY", None)
            no_display_result = run([*project_command, "config"], env=no_display)
            assert no_display_result.returncode != 0 and "DISPLAY" in no_display_result.stderr

            missing_auth = environment.copy()
            missing_auth["XAUTHORITY"] = str(task_dir / "authority file absent")
            negative_compose_launch("missing-auth", missing_auth, display, (cookie_one, cookie_two))

            missing_socket = environment.copy()
            missing_socket["X11_SOCKET_DIR"] = str(task_dir / "socket directory absent")
            negative_compose_launch("missing-socket", missing_socket, display, (cookie_one, cookie_two))

            wrong_cookie = secrets.token_hex(16)
            wrong_auth_file = task_dir / "wrong authority"
            write_host_authority(wrong_auth_file, display_number, wrong_cookie)
            wrong_env = {**environment, "XAUTHORITY": str(wrong_auth_file)}
            negative_compose_launch("wrong-cookie", wrong_env, display,
                                    (cookie_one, cookie_two, wrong_cookie), cookie_error=True)

            assert rotated_authority_hash != original_authority_hash
            assert hashlib.sha256(default_authority.read_bytes()).hexdigest() == rotated_authority_hash
            print("PASS production GUI Compose prep: authenticated Xvfb, HOME/custom authority, UID/mode, "
                  "rotation rejection/rebind, stop/restart, mode switch, and cleanup")
        finally:
            if attached is not None and attached.poll() is None:
                attached.send_signal(signal.SIGINT)
                attached.wait(timeout=30)
            for command in (project_command, compose(project, gui=False)):
                down = run([*command, "down", "--remove-orphans"], env=environment, timeout=180)
                assert down.returncode == 0, "task-owned GUI acceptance project cleanup failed"
            for name in (wallet, tor, authority_volume,
                         *(f"{project}_{suffix}" for suffix in (
                             "caddy-data", "caddy-config", "caddy-log", "fail2ban-state",
                             "caddy-ban-state", "caddy-control"))):
                remove_owned_volume(name)
            stop_xvfb(server)


if __name__ == "__main__":
    main()
