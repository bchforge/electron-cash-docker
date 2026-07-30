#!/usr/bin/env python3

import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_DEFAULTS = {}
for env_line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
    if "=" in env_line and not env_line.startswith("#"):
        env_key, env_value = env_line.split("=", 1)
        ENV_DEFAULTS[env_key] = env_value
IMAGE = f"electron-cash:{ENV_DEFAULTS['EC_VERSION']}"
PASSWORD = "cashfusion-test-password"
PYTHON = "/opt/electroncash-venv/bin/python"


def run(command, *, env=None, input_text=None):
    return subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        input=input_text,
        text=True,
        capture_output=True,
        check=False,
    )


def docker_python(case_dir, code, *, env=None):
    command = [
        "docker",
        "run",
        "--rm",
        "--user",
        f"{os.getuid()}:{os.getgid()}",
        "-e",
        "HOME=/home/ubuntu",
        "-v",
        f"{case_dir}:/case",
    ]
    for key, value in (env or {}).items():
        command.extend(["-e", f"{key}={value}"])
    command.extend(["--entrypoint", PYTHON, IMAGE, "-c", code])
    result = run(command)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def initialize_wallet(case_dir, encrypted, initial_autofuse):
    code = r'''
from electroncash.storage import WalletStorage
import os

storage = WalletStorage("/case/default_wallet", manual_upgrades=True)
storage.put("wallet_type", "standard")
storage.put("cashfusion_autofuse", os.environ["INITIAL_AUTOFUSE"] == "true")
if os.environ["ENCRYPTED"] == "true":
    storage.set_password(os.environ["TEST_PASSWORD"], True)
storage.write()
'''
    docker_python(
        case_dir,
        code,
        env={
            "ENCRYPTED": str(encrypted).lower(),
            "INITIAL_AUTOFUSE": str(initial_autofuse).lower(),
            "TEST_PASSWORD": PASSWORD,
        },
    )


def run_runtime_hook(case_dir, enabled, auto_fuse):
    code = r'''
import importlib.util
import json
import os

from electroncash.storage import WalletStorage
from electroncash_plugins.fusion.conf import Conf
from electroncash_plugins.fusion.qt import Plugin as FusionPlugin

spec = importlib.util.spec_from_file_location(
    "electroncash_wrapper", "/home/ubuntu/electroncash-wrapper.py"
)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)

storage = WalletStorage("/case/default_wallet", manual_upgrades=True)
encrypted_before = storage.is_encrypted()
if encrypted_before:
    storage.decrypt(os.environ["TEST_PASSWORD"])

class Wallet:
    def __init__(self, storage):
        self.storage = storage

    def print_error(self, *args):
        pass

wallet = Wallet(storage)
observed = {}

def original_on_new_window(_plugin, window):
    observed["value_in_original"] = Conf(window.wallet).autofuse

original_on_new_window._is_ec_plugin_hook = True
FusionPlugin.on_new_window = original_on_new_window
wrapper.patch_cashfusion_plugin_class(
    FusionPlugin,
    os.environ["CASHFUSION_ENABLED"] == "true",
    os.environ["CASHFUSION_AUTO_FUSE"] == "true",
)
assert FusionPlugin.on_new_window._is_ec_plugin_hook is True

class FakePlugin:
    @staticmethod
    def wallet_can_fuse(_wallet):
        return True

class Window:
    def __init__(self, wallet):
        self.wallet = wallet

FusionPlugin.on_new_window(FakePlugin(), Window(wallet))

print("RESULT=" + json.dumps({
    "autofuse": Conf(wallet).autofuse,
    "encrypted_before": encrypted_before,
    "encrypted_after": storage.is_encrypted(),
    "value_in_original": observed["value_in_original"],
}))
'''
    output = docker_python(
        case_dir,
        code,
        env={
            "CASHFUSION_ENABLED": str(enabled).lower(),
            "CASHFUSION_AUTO_FUSE": str(auto_fuse).lower(),
            "TEST_PASSWORD": PASSWORD,
        },
    )
    for line in output.splitlines():
        if line.startswith("RESULT="):
            return json.loads(line.removeprefix("RESULT="))
    raise AssertionError(f"No RESULT line found:\n{output}")


def is_encrypted(path):
    raw = path.read_text()
    try:
        return base64.b64decode(raw)[:4] == b"BIE1"
    except Exception:
        return False


def test_state(encrypted, enabled, auto_fuse):
    initial_autofuse = not auto_fuse if enabled else False

    with tempfile.TemporaryDirectory(prefix="cashfusion-state-") as temp_dir:
        case_dir = Path(temp_dir)
        wallet_path = case_dir / "default_wallet"
        config_path = case_dir / "config"

        initialize_wallet(case_dir, encrypted, initial_autofuse)
        wallet_before_config = wallet_path.read_bytes()
        config_path.write_text(
            json.dumps({"gui_last_wallet": str(wallet_path)}), encoding="utf-8"
        )

        env = os.environ.copy()
        env.update(
            {
                "CONFIG_FILE": str(config_path),
                "CASHFUSION_ENABLED": str(enabled).lower(),
                "CASHFUSION_AUTO_FUSE": str(auto_fuse).lower(),
            }
        )
        result = run(["bash", "docker/cashfusion.sh"], env=env)
        if result.returncode != 0:
            raise AssertionError(result.stdout + result.stderr)

        assert wallet_path.read_bytes() == wallet_before_config, (
            "cashfusion.sh modified wallet storage directly"
        )

        config = json.loads(config_path.read_text(encoding="utf-8"))
        assert config["use_fusion"] is enabled
        assert config["cashfusion_tor_host"] == "tor-proxy"
        assert config["cashfusion_tor_port_manual"] == 9050
        assert config["cashfusion_tor_port_auto"] is False

        runtime = run_runtime_hook(case_dir, enabled, auto_fuse)
        expected_autofuse = auto_fuse if enabled else initial_autofuse
        assert runtime["autofuse"] is expected_autofuse
        assert runtime["value_in_original"] is expected_autofuse
        assert runtime["encrypted_before"] is encrypted
        assert runtime["encrypted_after"] is encrypted
        assert is_encrypted(wallet_path) is encrypted


def test_invalid_values():
    with tempfile.TemporaryDirectory(prefix="cashfusion-invalid-") as temp_dir:
        config_path = Path(temp_dir) / "config"
        config_path.write_text("{}", encoding="utf-8")
        for variable in ("CASHFUSION_ENABLED", "CASHFUSION_AUTO_FUSE"):
            env = os.environ.copy()
            env.update(
                {
                    "CONFIG_FILE": str(config_path),
                    "CASHFUSION_ENABLED": "false",
                    "CASHFUSION_AUTO_FUSE": "false",
                    variable: "invalid",
                }
            )
            result = run(["bash", "docker/cashfusion.sh"], env=env)
            assert result.returncode == 1
            assert f"{variable} must be true or false" in result.stdout


def test_invalid_config_is_preserved():
    with tempfile.TemporaryDirectory(prefix="cashfusion-invalid-config-") as temp_dir:
        config_path = Path(temp_dir) / "config"
        invalid_config = "{truncated"
        config_path.write_text(invalid_config, encoding="utf-8")
        env = os.environ.copy()
        env.update(
            {
                "CONFIG_FILE": str(config_path),
                "CASHFUSION_ENABLED": "true",
                "CASHFUSION_AUTO_FUSE": "false",
            }
        )
        result = run(["bash", "docker/cashfusion.sh"], env=env)
        assert result.returncode != 0
        assert config_path.read_text(encoding="utf-8") == invalid_config


def test_public_defaults():
    assert ENV_DEFAULTS["CASHFUSION_ENABLED"] == "true"
    assert ENV_DEFAULTS["CASHFUSION_AUTO_FUSE"] == "false"
    assert ENV_DEFAULTS["WALLET_AUTO_CREATE"] == "false"
    assert ENV_DEFAULTS["TEST_WALLET_PASSWORD"] == ""


def test_entrypoint_rejects_unsafe_values():
    common_environment = [
        "-e",
        "CASHFUSION_ENABLED=true",
        "-e",
        "CASHFUSION_AUTO_FUSE=false",
    ]
    cases = (
        (["-e", "USE_TOR=invalid", "-e", "WALLET_DIR_HOST=./wallet"], "USE_TOR"),
        (["-e", "USE_TOR=true", "-e", "WALLET_DIR_HOST=/"], "WALLET_DIR"),
    )
    for environment, expected_message in cases:
        result = run(
            ["docker", "run", "--rm", *common_environment, *environment, IMAGE]
        )
        assert result.returncode == 1
        assert expected_message in result.stdout


def test_entrypoint_rejects_shared_wallet_directory():
    with tempfile.TemporaryDirectory(prefix="electron-cash-shared-wallet-") as temp_dir:
        shared_path = Path(temp_dir)
        unrelated_path = shared_path / "unrelated-data"
        unrelated_path.write_text("do not modify", encoding="utf-8")
        owner_before = shared_path.stat().st_uid, unrelated_path.stat().st_uid
        result = run(
            [
                "docker",
                "run",
                "--rm",
                "-e",
                "USE_TOR=true",
                "-e",
                f"WALLET_DIR_HOST={shared_path}",
                "-e",
                "CASHFUSION_ENABLED=true",
                "-e",
                "CASHFUSION_AUTO_FUSE=false",
                "-v",
                f"{shared_path}:/home/ubuntu/.electron-cash",
                IMAGE,
            ]
        )
        assert result.returncode == 1
        assert "must be empty on first use" in result.stdout
        assert (shared_path.stat().st_uid, unrelated_path.stat().st_uid) == owner_before
        assert unrelated_path.read_text(encoding="utf-8") == "do not modify"


def test_entrypoint_rejects_wallet_symlinks():
    with tempfile.TemporaryDirectory(prefix="electron-cash-wallet-link-") as temp_dir:
        wallet_path = Path(temp_dir) / "wallet"
        external_path = Path(temp_dir) / "external"
        wallet_path.mkdir()
        external_path.mkdir()
        (wallet_path / ".electron-cash-docker").write_text(
            "electron-cash-docker-v0.1\n", encoding="utf-8"
        )
        (wallet_path / "testnet4").symlink_to(external_path, target_is_directory=True)
        owner_before = external_path.stat().st_uid
        result = run(
            [
                "docker",
                "run",
                "--rm",
                "-e",
                "USE_TOR=true",
                "-e",
                f"WALLET_DIR_HOST={wallet_path}",
                "-e",
                "CASHFUSION_ENABLED=true",
                "-e",
                "CASHFUSION_AUTO_FUSE=false",
                "-e",
                "TESTNET4=true",
                "-v",
                f"{wallet_path}:/home/ubuntu/.electron-cash",
                IMAGE,
            ]
        )
        assert result.returncode == 1
        assert "must not contain symbolic links" in result.stdout
        assert external_path.stat().st_uid == owner_before


def test_test_wallet_password_hook():
    code = r'''
import importlib.util
import json

from electroncash.daemon import Daemon

spec = importlib.util.spec_from_file_location(
    "electroncash_wrapper", "/home/ubuntu/electroncash-wrapper.py"
)
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)

observed = {}

def original_load_wallet(_daemon, path, password):
    observed["path"] = path
    observed["password"] = password
    return "wallet"

Daemon.load_wallet = original_load_wallet
wrapper.install_test_wallet_password()
result = Daemon.load_wallet(object(), "/wallet", None)
print("RESULT=" + json.dumps({"observed": observed, "result": result}))
'''
    with tempfile.TemporaryDirectory(prefix="cashfusion-password-") as temp_dir:
        output = docker_python(
            Path(temp_dir),
            code,
            env={"TESTNET4": "true", "TEST_WALLET_PASSWORD": PASSWORD},
        )
    result_line = next(line for line in output.splitlines() if line.startswith("RESULT="))
    result = json.loads(result_line.removeprefix("RESULT="))
    assert result["result"] == "wallet"
    assert result["observed"] == {"path": "/wallet", "password": PASSWORD}


def test_mainnet_rejects_test_password():
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "USE_TOR=true",
            "-e",
            "WALLET_DIR_HOST=./wallet",
            "-e",
            "CASHFUSION_ENABLED=true",
            "-e",
            "CASHFUSION_AUTO_FUSE=false",
            "-e",
            "TEST_WALLET_PASSWORD=test-only",
            IMAGE,
        ]
    )
    assert result.returncode == 1
    assert "testnet4-only" in result.stdout


def main():
    test_public_defaults()
    test_invalid_values()
    test_invalid_config_is_preserved()
    test_entrypoint_rejects_unsafe_values()
    test_entrypoint_rejects_shared_wallet_directory()
    test_entrypoint_rejects_wallet_symlinks()
    test_test_wallet_password_hook()
    test_mainnet_rejects_test_password()

    for encrypted in (False, True):
        for enabled, auto_fuse in (
            (False, False),
            (False, True),
            (True, False),
            (True, True),
        ):
            test_state(encrypted, enabled, auto_fuse)
            storage = "encrypted" if encrypted else "plaintext"
            print(
                f"PASS {storage}: enabled={str(enabled).lower()} "
                f"auto_fuse={str(auto_fuse).lower()}"
            )

    print(
        "PASS invalid values, atomic config guard, public defaults, "
        "unsafe entrypoint values, and test-password guards"
    )


if __name__ == "__main__":
    main()
