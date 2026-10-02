#!/usr/bin/env python3
"""Mock the macOS services to prove reversible XQuartz setup under exit and signal."""
import os
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/mac-gui.sh"
SCENARIOS = json.loads((ROOT / "tests/fixtures/platform/mac-xquartz.json").read_text(encoding="utf-8"))["scenarios"]


def scenario(outcome, *, initially_running=False, nolisten="1", x11_bin=False, display=":0",
             delegated_cleanup=False, host_arch="x86_64", tor_platform="linux/amd64"):
    with tempfile.TemporaryDirectory(prefix="ecd-xquartz-mock-") as temporary:
        root = Path(temporary)
        tools = root / "bin"
        tools.mkdir()
        project = root / "project"
        (project / "scripts").mkdir(parents=True)
        fixture_script = project / "scripts/mac-gui.sh"
        shutil.copy2(SCRIPT, fixture_script)
        shutil.copy2(ROOT / "scripts/mac-compose-overlay.py", project / "scripts/mac-compose-overlay.py")
        fixture_script.write_text(fixture_script.read_text().replace(
            "xquartz_lock_file=/tmp/.X0-lock", 'xquartz_lock_file="$ECD_MOCK_X0_LOCK"'))
        (project / ".env").write_text("NETWORK=mainnet\n")
        platform_override = root / "image-platform.yml"
        platform_override.write_text(json.dumps({"services": {
            "electron-cash": {"platform": "linux/amd64"},
            "tor-proxy": {"platform": tor_platform},
        }}))
        app = root / "XQuartz.app"
        if outcome != "missing_xquartz":
            app.mkdir()
        tools_by_name = {
            "uname": 'if [ "$1" = "-m" ]; then echo "$ECD_MOCK_ARCH"; else echo Darwin; fi',
            "pgrep": 'case "$2" in X11) [ "$ECD_MOCK_X11_BIN" != true ] && [ -e "$ECD_MOCK_STATE" ] && printf "123\\n";; '
                     'X11.bin) [ "$ECD_MOCK_X11_BIN" = true ] && [ -e "$ECD_MOCK_STATE" ] && printf "123\\n";; '
                     '*) exit 2;; esac',
            "ps": 'if [ "$2" = 123 ] && [ -e "$ECD_MOCK_STATE" ]; then '
                  'printf "%s/Contents/MacOS/X11.bin\\n" "$XQUARTZ_APP"; else exit 1; fi',
            "osascript": 'echo osascript >> "$ECD_MOCK_LOG"; '
                         '[ "$ECD_MOCK_OUTCOME" != quit_cancel ] && '
                         '[ "$ECD_MOCK_OUTCOME" != quit_cancel_initial ] || exit 1; '
                         'rm -f "$ECD_MOCK_STATE" "$ECD_MOCK_X0_LOCK"',
            "open": ': > "$ECD_MOCK_STATE"; printf "123\\n" > "$ECD_MOCK_X0_LOCK"; '
                    'echo open >> "$ECD_MOCK_LOG"',
            "sleep": ':',
            "lsof": '[ "$ECD_MOCK_NO_LISTENER" != true ]',
            "xhost": 'echo xhost >> "$ECD_MOCK_LOG"',
            "defaults": 'echo "defaults $*" >> "$ECD_MOCK_LOG"; '
                       'if [ "$1" = read ]; then [ "$ECD_MOCK_HAS_SETTING" = true ] || exit 1; '
                       'if [ -f "$ECD_MOCK_PREF" ]; then IFS= read -r value < "$ECD_MOCK_PREF"; printf "%s\\n" "$value"; '
                       'elif [ "$ECD_MOCK_HAS_SETTING" = true ]; then printf "%s\\n" "$ECD_MOCK_NOLISTEN"; else exit 1; fi; exit 0; fi; '
                        'if [ "$1" = write ]; then '
                        '[ "$ECD_MOCK_SETUP_FAIL" != true ] || [ "$5" != false ] || exit 8; '
                        '[ "$ECD_MOCK_RESTORE_FAIL" != true ] || [ "$5" != true ] || exit 9; '
                        'value=$5; [ "$5" != true ] || value=1; [ "$5" != false ] || value=0; '
                        'printf "%s\\n" "$value" > "$ECD_MOCK_PREF"; exit 0; fi; '
                       'if [ "$1" = delete ]; then rm -f "$ECD_MOCK_PREF"; exit 0; fi; exit 0',
             "xauth": 'case "$1" in list|nlist) [ "$ECD_MOCK_XAUTH_DENIED" != true ] || { echo "xauth: permission denied" >&2; exit 13; }; '
                       'if [ "$ECD_MOCK_NO_COOKIE" != true ] && [ "$2" = "$ECD_MOCK_AUTH_DISPLAY" ]; then '
                       'if [ "$1" = list ]; then echo "xquartz/unix:0 MIT-MAGIC-COOKIE-1 010000000000"; '
                       'else echo "010000000000"; fi; fi;; -f) : > "$2";; esac',
            "docker": 'echo "docker $*" >> "$ECD_MOCK_LOG"; '
                      'case "$*" in *"config --format json"*) printf \'{"name":"ecd-mock-project"}\\n\'; exit 0;; esac; '
                      'case "$*" in *"ps -a -q"*) [ "$ECD_MOCK_EXISTING_CONTAINER" != true ] || { printf "foreign-container\\n"; exit 0; };; esac; '
                      'case "$*" in *"network ls -q"*) [ "$ECD_MOCK_EXISTING_NETWORK" != true ] || { printf "foreign-network\\n"; exit 0; };; esac; '
                      'if [ "$1" = info ] && [ "$ECD_MOCK_DOCKER_OFFLINE" = true ]; then exit 9; fi; '
                      'case "$*" in *"up -d --build --no-deps tor-proxy"*) '
                       'case "$ECD_MOCK_OUTCOME" in fail_tor) exit 7;; signal_tor) kill -TERM "$PPID";; signal_tor_int) kill -INT "$PPID";; esac;; esac; '
                       'case "$*" in *"up --no-build --no-deps electron-cash"*) '
                       'case "$ECD_MOCK_OUTCOME" in fail|stale_cookie) exit 7;; signal) kill -TERM "$PPID";; signal_int) kill -INT "$PPID";; esac;; esac; '
                      'case "$*" in *"down --remove-orphans"*) [ "$ECD_MOCK_OUTCOME" != cleanup_fail ] || exit 7;; esac',
        }
        for name, body in tools_by_name.items():
            path = tools / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        bash_env = root / "bash-env"
        bash_env.write_text('xauth() { "$ECD_MOCK_XAUTH" "$@"; }\n'
                            'kill() { echo "kill $*" >> "$ECD_MOCK_LOG"; '
                            '[ "$1" != -TERM ] || rm -f "$ECD_MOCK_STATE"; }\n')
        log = root / "calls"
        state = root / "running"
        if initially_running:
            state.touch()
        env = {**os.environ, "PATH": f"{tools}:{os.environ['PATH']}",
               "XQUARTZ_APP": str(app), "ECD_MOCK_STATE": str(state),
               "ECD_MOCK_X0_LOCK": str(root / "X0-lock"),
               "ECD_MOCK_PREF": str(root / "nolisten-pref"),
                "ECD_MOCK_LOG": str(log), "ECD_MOCK_OUTCOME": outcome,
                "ECD_MOCK_X11_BIN": "true" if x11_bin else "false",
                "ECD_MOCK_ARCH": host_arch,
                "ECD_MOCK_AUTH_DISPLAY": ":0",
               "ECD_MOCK_NOLISTEN": nolisten,
               "ECD_MOCK_HAS_SETTING": "false" if outcome == "preference_unset" else "true",
               "ECD_MOCK_NO_LISTENER": "true" if outcome == "listener_unavailable" else "false",
               "ECD_MOCK_NO_COOKIE": "true" if outcome == "cookie_missing" else "false",
               "ECD_MOCK_XAUTH_DENIED": "true" if outcome == "xauth_denied" else "false",
               "ECD_MOCK_DOCKER_OFFLINE": "true" if outcome == "docker_offline" else "false",
               "ECD_MOCK_SETUP_FAIL": "true" if outcome == "setup_fail" else "false",
                "ECD_MOCK_RESTORE_FAIL": "true" if outcome == "restore_fail" else "false",
                "ECD_MOCK_EXISTING_CONTAINER": "true" if outcome == "existing_container" else "false",
                "ECD_MOCK_EXISTING_NETWORK": "true" if outcome == "existing_network" else "false",
                "ECD_MOCK_XAUTH": str(tools / "xauth"), "BASH_ENV": str(bash_env),
                "ECD_PLATFORM_OVERRIDE": str(platform_override),
                "CI_DOCKER_OWNER_SHIM": "1" if delegated_cleanup else "0",
                "CI_RESOURCE_OWNER": "runner-owner" if delegated_cleanup else "",
                "CI_RESOURCE_REGISTRY": str(root / "owned-resources.jsonl") if delegated_cleanup else "",
                "DISPLAY": display}
        result = subprocess.run(["bash", str(fixture_script)], cwd=project, env=env,
                                capture_output=True, text=True, timeout=20)
        calls = log.read_text() if log.exists() else ""
        if outcome == "missing_xquartz":
            assert result.returncode != 0 and SCENARIOS["missing-xquartz"]["expected_error"] in result.stderr
            assert "defaults write" not in calls
            return result
        if outcome in ("existing_container", "existing_network"):
            assert result.returncode != 0
            assert "refusing XQuartz cleanup authority" in result.stderr
            assert "defaults write" not in calls and "up -d" not in calls
            assert str(platform_override) in calls
            return result
        assert log.exists(), (result.returncode, result.stdout, result.stderr)
        if outcome != "docker_offline":
            assert str(platform_override) in calls, calls
        assert "xhost" not in calls, calls
        if outcome == "docker_offline":
            assert "start Docker Desktop" in result.stderr
            assert "defaults write" not in calls
        elif outcome == "restore_fail":
            assert result.returncode != 0
            assert calls.count("defaults write org.xquartz.X11 nolisten_tcp -bool true") == 3
            assert "XQuartz will remain stopped" in result.stderr
            assert not state.exists()
        elif outcome == "setup_fail":
            assert result.returncode != 0
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool false" in calls
            assert not state.exists()
        elif outcome in ("listener_unavailable", "cookie_missing", "stale_cookie"):
            assert result.returncode != 0
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool false" in calls
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool true" in calls
            assert not state.exists()
        elif outcome == "preference_unset":
            assert result.returncode == 0
            assert "defaults delete org.xquartz.X11 nolisten_tcp" in calls
            assert not state.exists()
        elif outcome == "xauth_denied":
            assert result.returncode != 0 and "unable to read XQuartz MIT-MAGIC-COOKIE-1 authority" in result.stderr
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool true" in calls
            assert not state.exists()
        elif outcome == "cleanup_fail":
            assert result.returncode != 0
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool true" in calls
            assert not state.exists()
        elif outcome == "quit_cancel":
            assert result.returncode == 0, (result.stdout, result.stderr)
            assert "kill -TERM 123" in calls
            assert not state.exists()
            assert not (root / "X0-lock").exists()
        elif outcome == "quit_cancel_initial":
            assert result.returncode != 0
            assert "kill " not in calls
            assert state.exists()
        elif nolisten == "0":
            assert "defaults write" not in calls, calls
            if initially_running:
                assert "osascript" not in calls, calls
            assert state.exists() == initially_running
        else:
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool false" in calls, calls
            assert "defaults write org.xquartz.X11 nolisten_tcp -bool true" in calls, calls
            assert state.exists() == initially_running
        if delegated_cleanup:
            assert "down --remove-orphans" not in calls, calls
        elif "up -d --build --no-deps tor-proxy" in calls:
            assert "down --remove-orphans" in calls, calls
        return result


def main():
    success = scenario("success")
    assert success.returncode == 0, (success.stdout, success.stderr)
    assert scenario("fail").returncode != 0
    assert scenario("fail_tor").returncode != 0
    assert scenario("signal").returncode != 0
    assert scenario("signal_int").returncode != 0
    assert scenario("signal_tor").returncode != 0
    assert scenario("signal_tor_int").returncode != 0
    assert scenario("success", initially_running=True, nolisten="0").returncode == 0
    assert scenario("success", initially_running=True, nolisten="0", x11_bin=True).returncode == 0
    assert scenario("success", initially_running=True, nolisten="1").returncode == 0
    assert scenario("success", display="/var/run/com.apple.launchd.test/org.xquartz:0").returncode == 0
    assert scenario("success", delegated_cleanup=True).returncode == 0
    assert scenario("success", host_arch="arm64", tor_platform="linux/arm64").returncode == 0
    assert scenario("success", initially_running=False, nolisten="0").returncode == 0
    assert scenario("docker_offline").returncode != 0
    assert scenario("listener_unavailable").returncode != 0
    assert scenario("cookie_missing").returncode != 0
    assert scenario("stale_cookie").returncode != 0
    assert scenario("xauth_denied").returncode != 0
    assert scenario("setup_fail").returncode != 0
    assert scenario("restore_fail").returncode != 0
    assert scenario("cleanup_fail").returncode != 0
    assert scenario("quit_cancel").returncode == 0
    assert scenario("quit_cancel_initial", initially_running=True).returncode != 0
    assert scenario("preference_unset").returncode == 0
    scenario("missing_xquartz")
    scenario("existing_container")
    scenario("existing_network")
    assert SCENARIOS["no-unrestricted-xhost"]["forbidden_operation"] not in SCRIPT.read_text()
    with tempfile.TemporaryDirectory(prefix="ecd-xquartz-compose-contract-") as temporary:
        root = Path(temporary)
        authority = root / "authority path" / "Xauthority"
        authority.parent.mkdir(mode=0o700)
        authority.write_bytes(b"synthetic XQuartz authorization"); authority.chmod(0o600)
        override = root / "mac-compose.yml"
        generated = subprocess.run(["python3", str(ROOT / "scripts/mac-compose-overlay.py"),
                                     str(override), str(authority)], text=True,
                                   capture_output=True, check=False, timeout=10)
        assert generated.returncode == 0
        env = {**os.environ, "BASIC_AUTH_PASSWORD": "synthetic-mac-config",
               "DISPLAY": "host.docker.internal:0", "XAUTHORITY": str(authority)}
        command = ["docker", "compose", "--project-directory", str(ROOT),
                   "--env-file", str(ROOT / ".env.example"), "-p", "ecd-mac-resolved-config",
                   "-f", str(ROOT / "docker-compose.yml"), "-f", str(ROOT / "docker-compose.gui.yml"),
                   "-f", str(override), "config", "--format", "json"]
        resolved = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                  capture_output=True, check=False, timeout=60)
        assert resolved.returncode == 0, "XQuartz generated Compose override did not resolve"
        model = json.loads(resolved.stdout)
        wallet = model["services"]["electron-cash"]
        assert wallet["environment"]["XAUTHORITY"] == "/home/electroncash/.Xauthority"
        assert [volume["target"] for volume in wallet["volumes"]] == [
            "/home/electroncash/.electron-cash", "/home/electroncash/.Xauthority"]
        cookie_mount = wallet["volumes"][1]
        assert cookie_mount["source"] == str(authority) and cookie_mount["read_only"]
        assert "x11-authority" in model["services"]
        assert 'up --no-build --no-deps electron-cash' in SCRIPT.read_text()
    print("PASS XQuartz mocks: restore on success, failure and signal without xhost changes")


if __name__ == "__main__":
    main()
