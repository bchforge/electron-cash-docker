#!/usr/bin/env python3

import json
import os
import re
import subprocess
import tempfile
import sys
from contextlib import contextmanager
from pathlib import Path

from test_support import electron_cash_image, unique_resource


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker"))
from cashfusion_defaults import (  # noqa: E402
    cashfusion_config_from_environment,
)

ENV_DEFAULTS = {}
for env_line in (ROOT / ".env.example").read_text(encoding="utf-8").splitlines():
    if "=" in env_line and not env_line.startswith("#"):
        env_key, env_value = env_line.split("=", 1)
        ENV_DEFAULTS[env_key] = env_value
IMAGE = electron_cash_image()
PASSWORD = "cashfusion-test-password"
PYTHON = "/opt/electroncash-venv/bin/python"
SUPPORTED_CASHFUSION_ENV = (
    "CASHFUSION_ENABLED",
    "CASHFUSION_AUTO_FUSE",
    "CASHFUSION_FUSION_MODE",
    "CASHFUSION_FUSE_DEPTH",
    "CASHFUSION_SELF_FUSE_PLAYERS",
    "CASHFUSION_SELECTOR_MODE",
    "CASHFUSION_SELECTOR_COUNT",
    "CASHFUSION_SELECTOR_SIZE_BCH",
    "CASHFUSION_SELECTOR_FRACTION",
    "CASHFUSION_QUEUED_AUTOFUSE",
    "CASHFUSION_AUTOFUSE_CONFIRMED_ONLY",
    "CASHFUSION_FEE_BUDGET",
    "CASHFUSION_MIN_UTXO",
)
REMOVED_CASHFUSION_ENV = (
    "CASHFUSION_TOR_HOST",
    "CASHFUSION_TOR_PORT",
    "CASHFUSION_TARGET",
)


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


@contextmanager
def disposable_volume(prefix):
    name = unique_resource(prefix)
    created = run(
        ["docker", "volume", "create", "--label", "com.bchforge.test=true", name]
    )
    if created.returncode != 0:
        raise AssertionError(created.stdout + created.stderr)
    prepared = run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0:0",
            "--mount",
            f"type=volume,src={name},dst=/case",
            "--entrypoint",
            "/bin/bash",
            IMAGE,
            "-c",
            "chown 10001:10001 /case && chmod 700 /case",
        ]
    )
    if prepared.returncode != 0:
        run(["docker", "volume", "rm", name])
        raise AssertionError(prepared.stdout + prepared.stderr)
    try:
        yield name
    finally:
        run(["docker", "volume", "rm", name])


def docker_python(volume, code, *, env=None):
    command = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--user",
        "10001:10001",
        "-e",
        "HOME=/home/electroncash",
        "--mount",
        f"type=volume,src={volume},dst=/case",
    ]
    for key, value in (env or {}).items():
        command.extend(["-e", f"{key}={value}"])
    command.extend(["--entrypoint", PYTHON, IMAGE, "-c", code])
    result = run(command)
    if result.returncode != 0:
        raise AssertionError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def initialize_wallet(volume, encrypted, settings=None):
    code = r'''
from electroncash.storage import WalletStorage
import os
import json

storage = WalletStorage("/case/default_wallet", manual_upgrades=True)
storage.put("wallet_type", "standard")
for key, value in json.loads(os.environ["INITIAL_SETTINGS"]).items():
    storage.put(key, value)
if os.environ["ENCRYPTED"] == "true":
    storage.set_password(os.environ["TEST_PASSWORD"], True)
storage.write()
'''
    docker_python(
        volume,
        code,
        env={
            "ENCRYPTED": str(encrypted).lower(),
            "INITIAL_SETTINGS": json.dumps(settings or {}),
            "TEST_PASSWORD": PASSWORD,
        },
    )


def cashfusion_environment(enabled, overrides=None):
    environment = dict(overrides or {})
    environment["CASHFUSION_ENABLED"] = str(enabled).lower()
    return environment


def run_cashfusion(volume, enabled, overrides=None):
    code = r'''
import json
import os
import subprocess
from pathlib import Path

wallet_path = Path("/case/default_wallet")
config_path = Path("/case/config")
wallet_before = wallet_path.read_bytes()
config_path.write_text(json.dumps({"gui_last_wallet": str(wallet_path)}), encoding="utf-8")
result = subprocess.run(
    ["bash", "/home/electroncash/cashfusion.sh"],
    capture_output=True,
    text=True,
    env=os.environ.copy(),
)
if result.returncode != 0:
    raise SystemExit(result.stdout + result.stderr)

print("RESULT=" + json.dumps({
    "wallet_unchanged": wallet_path.read_bytes() == wallet_before,
    "config": json.loads(config_path.read_text(encoding="utf-8")),
}))
'''
    output = docker_python(
        volume,
        code,
        env={
            "CONFIG_FILE": "/case/config",
            **cashfusion_environment(enabled, overrides),
        },
    )
    for line in output.splitlines():
        if line.startswith("RESULT="):
            return json.loads(line.removeprefix("RESULT="))
    raise AssertionError(f"No RESULT line found:\n{output}")


def run_runtime_hook(volume, enabled, overrides=None):
    code = r'''
import importlib.util
import inspect
import json
import os

from electroncash.storage import WalletStorage
from electroncash_plugins.fusion.conf import Conf
from electroncash_plugins.fusion.qt import Plugin as FusionPlugin

spec = importlib.util.spec_from_file_location(
    "electroncash_wrapper", "/home/electroncash/electroncash-wrapper.py"
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

def original_add_wallet(_plugin, wallet, _password=None):
    observed["value_in_add_wallet"] = Conf(wallet).autofuse

FusionPlugin.add_wallet = original_add_wallet
if os.environ["CASHFUSION_ENABLED"] == "true":
    patch_parameters = inspect.signature(
        wrapper.patch_cashfusion_plugin_class
    ).parameters
    patch_kwargs = {
        name: True
        for name in ("enabled", "auto_fuse")
        if name in patch_parameters
    }
    wrapper.patch_cashfusion_plugin_class(FusionPlugin, **patch_kwargs)
    assert FusionPlugin._docker_defaults_patched is True

class FakePlugin:
    @staticmethod
    def wallet_can_fuse(_wallet):
        return True

class Window:
    def __init__(self, wallet):
        self.wallet = wallet

FusionPlugin.on_new_window(FakePlugin(), Window(wallet))
FusionPlugin.add_wallet(FakePlugin(), wallet)

keys = (
    "cashfusion_autofuse",
    "cashfusion_fusion_mode",
    "cashfusion_fuse_depth",
    "cashfusion_self_fuse_players",
    "cashfusion_selector",
    "cashfusion_queued_autofuse",
    "cashfusion_autofuse_only_when_all_confirmed",
)

print("RESULT=" + json.dumps({
    "autofuse": Conf(wallet).autofuse,
    "fusion_mode": Conf(wallet).fusion_mode,
    "fuse_depth": Conf(wallet).fuse_depth,
    "self_fuse_players": Conf(wallet).self_fuse_players,
    "selector": list(Conf(wallet).selector),
    "queued_autofuse": Conf(wallet).queued_autofuse,
    "confirmed_only": Conf(wallet).autofuse_confirmed_only,
    "raw": {key: storage.get(key, "__missing__") for key in keys},
    "encrypted_before": encrypted_before,
    "encrypted_after": storage.is_encrypted(),
    "value_in_original": observed["value_in_original"],
    "value_in_add_wallet": observed["value_in_add_wallet"],
}))
'''
    output = docker_python(
        volume,
        code,
        env={
            "TEST_PASSWORD": PASSWORD,
            **cashfusion_environment(enabled, overrides),
        },
    )
    for line in output.splitlines():
        if line.startswith("RESULT="):
            return json.loads(line.removeprefix("RESULT="))
    raise AssertionError(f"No RESULT line found:\n{output}")


def run_daemon_runtime_hook(volume, enabled, encrypted, overrides=None):
    code = r'''
import importlib.util
import json
import os

from electroncash.daemon import Daemon
from electroncash.storage import WalletStorage
from electroncash_plugins.fusion.conf import Conf

spec = importlib.util.spec_from_file_location(
    "electroncash_daemon_wrapper", "/home/electroncash/electroncash-daemon-wrapper.py"
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

class FusionPlugin:
    @staticmethod
    def wallet_can_fuse(_wallet):
        return True

    def add_wallet(self, wallet, password=None):
        observed["password"] = password
        observed["autofuse_in_add_wallet"] = Conf(wallet).autofuse

class Plugins:
    def get_internal_plugin(self, name):
        assert name == "fusion"
        return FusionPlugin()

class FakeDaemon:
    plugins = Plugins()

def original_load_wallet(_daemon, _path, password):
    observed["password_in_load_wallet"] = password
    return wallet

Daemon.load_wallet = original_load_wallet
if os.environ["CASHFUSION_ENABLED"] == "true":
    wrapper.install_cashfusion_defaults()
loaded = Daemon.load_wallet(FakeDaemon(), "/case/default_wallet", "accepted-password")

print("RESULT=" + json.dumps({
    "autofuse": Conf(loaded).autofuse,
    "fusion_mode": Conf(loaded).fusion_mode,
    "fuse_depth": Conf(loaded).fuse_depth,
    "self_fuse_players": Conf(loaded).self_fuse_players,
    "selector": list(Conf(loaded).selector),
    "queued_autofuse": Conf(loaded).queued_autofuse,
    "confirmed_only": Conf(loaded).autofuse_confirmed_only,
    "raw": {key: loaded.storage.get(key, "__missing__") for key in (
        "cashfusion_autofuse",
        "cashfusion_fusion_mode",
        "cashfusion_fuse_depth",
        "cashfusion_self_fuse_players",
        "cashfusion_selector",
        "cashfusion_queued_autofuse",
        "cashfusion_autofuse_only_when_all_confirmed",
    )},
    "encrypted_before": encrypted_before,
    "encrypted_after": storage.is_encrypted(),
    "observed": observed,
}))
'''
    output = docker_python(
        volume,
        code,
        env={
            "TEST_PASSWORD": PASSWORD,
            **cashfusion_environment(enabled, overrides),
        },
    )
    for line in output.splitlines():
        if line.startswith("RESULT="):
            return json.loads(line.removeprefix("RESULT="))
    raise AssertionError(f"No RESULT line found:\n{output}")


def profile_for_environment(overrides=None):
    environment = {"CASHFUSION_ENABLED": "true"}
    environment.update(overrides or {})
    return cashfusion_config_from_environment(environment)["profile"]


def test_state(encrypted, enabled, settings=None, overrides=None):
    with disposable_volume("cashfusion-state") as volume:
        initialize_wallet(volume, encrypted, settings)
        runtime_config = run_cashfusion(volume, enabled, overrides)

        assert runtime_config["wallet_unchanged"]
        config = runtime_config["config"]
        assert config["use_fusion"] is enabled
        assert config["cashfusion_tor_host"] == "tor-proxy"
        assert config["cashfusion_tor_port_manual"] == 9050
        assert config["cashfusion_tor_port_auto"] is False

        runtime = run_runtime_hook(volume, enabled, overrides)
        if enabled:
            profile = profile_for_environment(overrides)
            profile.update(settings or {})
            assert runtime["autofuse"] is profile["cashfusion_autofuse"]
            assert runtime["fusion_mode"] == profile["cashfusion_fusion_mode"]
            assert runtime["fuse_depth"] == profile["cashfusion_fuse_depth"]
            assert runtime["self_fuse_players"] == profile["cashfusion_self_fuse_players"]
            assert runtime["selector"] == profile["cashfusion_selector"]
            assert runtime["queued_autofuse"] == profile["cashfusion_queued_autofuse"]
            assert runtime["confirmed_only"] is profile["cashfusion_autofuse_only_when_all_confirmed"]
            assert runtime["raw"] == profile
            assert runtime["value_in_original"] is profile["cashfusion_autofuse"]
            assert runtime["value_in_add_wallet"] is profile["cashfusion_autofuse"]
        else:
            assert all(value == "__missing__" for value in runtime["raw"].values())
            assert runtime["autofuse"] is False
            assert runtime["value_in_original"] is False
            assert runtime["value_in_add_wallet"] is False
        assert runtime["encrypted_before"] is encrypted
        assert runtime["encrypted_after"] is encrypted

        daemon_runtime = run_daemon_runtime_hook(
            volume, enabled, encrypted, overrides
        )
        if enabled:
            assert daemon_runtime["autofuse"] is runtime["autofuse"]
            assert daemon_runtime["fusion_mode"] == runtime["fusion_mode"]
            assert daemon_runtime["fuse_depth"] == runtime["fuse_depth"]
            assert daemon_runtime["self_fuse_players"] == runtime["self_fuse_players"]
            assert daemon_runtime["selector"] == runtime["selector"]
            assert daemon_runtime["queued_autofuse"] == runtime["queued_autofuse"]
            assert daemon_runtime["confirmed_only"] is runtime["confirmed_only"]
            assert daemon_runtime["raw"] == runtime["raw"]
        else:
            assert all(value == "__missing__" for value in daemon_runtime["raw"].values())
            assert daemon_runtime["autofuse"] is False
        assert daemon_runtime["encrypted_before"] is encrypted
        assert daemon_runtime["encrypted_after"] is encrypted
        assert daemon_runtime["observed"]["password_in_load_wallet"] == "accepted-password"
        if enabled:
            assert daemon_runtime["observed"]["autofuse_in_add_wallet"] is runtime["autofuse"]
            assert daemon_runtime["observed"]["password"] == "accepted-password"
        else:
            assert "autofuse_in_add_wallet" not in daemon_runtime["observed"]


def test_gui_change_survives_default_restart():
    with disposable_volume("cashfusion-gui") as volume:
        initialize_wallet(volume, encrypted=False)
        initial = run_runtime_hook(volume, enabled=True)
        assert initial["autofuse"] is False
        assert initial["selector"] == ["count", 10]
        assert initial["value_in_original"] is False
        assert initial["value_in_add_wallet"] is False

        docker_python(
            volume,
            """
from electroncash.storage import WalletStorage

storage = WalletStorage('/case/default_wallet', manual_upgrades=True)
storage.put('cashfusion_autofuse', True)
storage.write()
""",
        )
        restarted = run_runtime_hook(volume, enabled=True)
        assert restarted["autofuse"] is True
        assert restarted["selector"] == ["count", 10]
        assert restarted["raw"]["cashfusion_autofuse"] is True


def test_auto_fuse_later_uses_persisted_target_count():
    with disposable_volume("cashfusion-auto-fuse") as volume:
        initialize_wallet(volume, encrypted=False)
        run_cashfusion(volume, enabled=True)
        initial = run_runtime_hook(volume, enabled=True)
        assert initial["autofuse"] is False
        assert initial["selector"] == ["count", 10]

        docker_python(
            volume,
            """
from electroncash.storage import WalletStorage

storage = WalletStorage('/case/default_wallet', manual_upgrades=True)
storage.put('cashfusion_autofuse', True)
storage.write()
""",
        )
        enabled_later = run_runtime_hook(
            volume,
            enabled=True,
            overrides={"CASHFUSION_AUTO_FUSE": "true"},
        )
        assert enabled_later["autofuse"] is True
        assert enabled_later["selector"] == ["count", 10]
        assert enabled_later["raw"]["cashfusion_selector"] == ["count", 10]


def test_disable_restart_reenable_preserves_gui_choice():
    with disposable_volume("cashfusion-reenable") as volume:
        initialize_wallet(volume, encrypted=False)
        run_cashfusion(volume, enabled=True)
        initial = run_runtime_hook(volume, enabled=True)
        assert initial["selector"] == ["count", 10]

        docker_python(
            volume,
            """
from electroncash.storage import WalletStorage

storage = WalletStorage('/case/default_wallet', manual_upgrades=True)
storage.put('cashfusion_autofuse', True)
storage.put('cashfusion_selector', ['size', 100000])
storage.write()
""",
        )
        disabled = run_cashfusion(volume, enabled=False)
        assert disabled["config"]["use_fusion"] is False

        run_cashfusion(volume, enabled=True)
        reenabled = run_runtime_hook(volume, enabled=True)
        assert reenabled["autofuse"] is True
        assert reenabled["selector"] == ["size", 100000]
        assert reenabled["raw"]["cashfusion_selector"] == ["size", 100000]


def test_invalid_values():
    invalid_values = (
        (
            "CASHFUSION_ENABLED",
            "invalid",
            "CASHFUSION_ENABLED must be true or false",
        ),
        ("CASHFUSION_AUTO_FUSE", "maybe", "CASHFUSION_AUTO_FUSE must be true or false"),
        ("CASHFUSION_FUSE_DEPTH", "not-an-int", "CASHFUSION_FUSE_DEPTH must be an integer"),
        (
            "CASHFUSION_SELECTOR_MODE",
            "invalid",
            "CASHFUSION_SELECTOR_MODE must be one of",
        ),
        ("CASHFUSION_FUSE_DEPTH", "11", "CASHFUSION_FUSE_DEPTH must be between 0 and 10"),
        (
            "CASHFUSION_SELECTOR_SIZE_BCH",
            "0",
            "CASHFUSION_SELECTOR_SIZE_BCH must be greater than 0",
        ),
        (
            "CASHFUSION_SELECTOR_FRACTION",
            "1.1",
            "CASHFUSION_SELECTOR_FRACTION must be between 0.0 and 1.0",
        ),
    )
    for key, value, message in invalid_values:
        with tempfile.TemporaryDirectory(prefix="cashfusion-invalid-") as temp_dir:
            config_path = Path(temp_dir) / "config"
            config_path.write_text("{}", encoding="utf-8")
            env = os.environ.copy()
            env.update(
                {
                    "CONFIG_FILE": str(config_path),
                    "CASHFUSION_ENABLED": "true",
                    key: value,
                }
            )
            if key == "CASHFUSION_SELECTOR_SIZE_BCH":
                env["CASHFUSION_SELECTOR_MODE"] = "size"
            elif key == "CASHFUSION_SELECTOR_FRACTION":
                env["CASHFUSION_SELECTOR_MODE"] = "fraction"
            result = run(["bash", "docker/cashfusion.sh"], env=env)
            assert result.returncode == 1
            assert message in result.stdout + result.stderr
            assert config_path.read_text(encoding="utf-8") == "{}"


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
            }
        )
        result = run(["bash", "docker/cashfusion.sh"], env=env)
        assert result.returncode != 0
        assert config_path.read_text(encoding="utf-8") == invalid_config


def test_wallet_lifecycle():
    code = r'''
import json
import os
import subprocess
from pathlib import Path

config_path = Path("/case/config")
result = subprocess.run(
    ["bash", "/home/electroncash/cashfusion.sh"],
    env={**os.environ, "CONFIG_FILE": str(config_path)},
    capture_output=True,
    text=True,
)
if result.returncode != 0:
    raise SystemExit(result.stdout + result.stderr)
print("RESULT=" + json.dumps({
    "wallet_exists": Path("/case/default_wallet").exists(),
    "use_fusion": json.loads(config_path.read_text(encoding="utf-8"))["use_fusion"],
}))
'''
    with disposable_volume("cashfusion-lifecycle") as volume:
        output = docker_python(
            volume,
            code,
            env=cashfusion_environment(True),
        )
        result_line = next(line for line in output.splitlines() if line.startswith("RESULT="))
        result = json.loads(result_line.removeprefix("RESULT="))
        assert result == {"wallet_exists": False, "use_fusion": True}

        initialize_wallet(volume, encrypted=False)
        runtime = run_runtime_hook(volume, enabled=True)
        assert runtime["raw"]["cashfusion_fuse_depth"] == 3
        assert runtime["raw"]["cashfusion_selector"] == ["count", 10]


def test_public_defaults():
    assert ENV_DEFAULTS["CASHFUSION_ENABLED"] == "true"
    assert tuple(key for key in ENV_DEFAULTS if key.startswith("CASHFUSION_")) == SUPPORTED_CASHFUSION_ENV
    assert {key: ENV_DEFAULTS[key] for key in SUPPORTED_CASHFUSION_ENV} == {
        "CASHFUSION_ENABLED": "true",
        "CASHFUSION_AUTO_FUSE": "false",
        "CASHFUSION_FUSION_MODE": "custom",
        "CASHFUSION_FUSE_DEPTH": "3",
        "CASHFUSION_SELF_FUSE_PLAYERS": "1",
        "CASHFUSION_SELECTOR_MODE": "count",
        "CASHFUSION_SELECTOR_COUNT": "10",
        "CASHFUSION_SELECTOR_SIZE_BCH": "0.0001",
        "CASHFUSION_SELECTOR_FRACTION": "1.0",
        "CASHFUSION_QUEUED_AUTOFUSE": "4",
        "CASHFUSION_AUTOFUSE_CONFIRMED_ONLY": "true",
        "CASHFUSION_FEE_BUDGET": "0",
        "CASHFUSION_MIN_UTXO": "1000",
    }
    assert ENV_DEFAULTS["WALLET_AUTO_CREATE"] == "false"
    assert ENV_DEFAULTS["TEST_WALLET_PASSWORD"] == ""


def test_compose_cashfusion_environment():
    environment = os.environ.copy()
    for key in SUPPORTED_CASHFUSION_ENV:
        environment.pop(key, None)
    environment["BASIC_AUTH_PASSWORD"] = "synthetic-auth-secret"
    with tempfile.TemporaryDirectory(prefix="cashfusion-compose-") as temp_dir:
        old_env = Path(temp_dir) / "old.env"
        old_env.write_text(
            "\n".join(
                line
                for line in (ROOT / ".env.example").read_text().splitlines()
                if not line.startswith("CASHFUSION_")
            )
            + "\n",
            encoding="utf-8",
        )
        for env_file in (".env.example", str(old_env)):
            for compose_files in (
                ["docker-compose.yml"],
                ["docker-compose.yml", "docker-compose.headless.yml"],
            ):
                result = run(
                    [
                        "docker",
                        "compose",
                        "--env-file",
                        env_file,
                        *sum((["-f", path] for path in compose_files), []),
                        "config",
                        "--format",
                        "json",
                    ],
                    env=environment,
                )
                assert result.returncode == 0, result.stdout + result.stderr
                model = json.loads(result.stdout)
                service_environment = model["services"]["electron-cash"]["environment"]
                assert set(SUPPORTED_CASHFUSION_ENV) <= set(service_environment)
                assert service_environment["CASHFUSION_ENABLED"] == "true"
                assert service_environment["CASHFUSION_AUTO_FUSE"] == "false"


def test_removed_cashfusion_environment_is_absent_from_public_surfaces():
    public_paths = [
        ROOT / ".env.example",
        ROOT / "README.md",
        *ROOT.glob("docker-compose*.yml"),
        *ROOT.glob("docker/*"),
        *ROOT.glob("docs/*.md"),
        *ROOT.glob("scripts/*.py"),
    ]
    for path in public_paths:
        if not path.is_file():
            continue
        text = path.read_text(encoding="utf-8")
        for variable in REMOVED_CASHFUSION_ENV:
            for line in text.splitlines():
                if variable not in line:
                    continue
                # Documentation may explicitly identify an unsupported legacy
                # knob; it must not publish an assignment or imply support.
                assert path.suffix == ".md", (path, variable)
                assert any(phrase in line for phrase in ("unsupported", "not supported", "sin admitirse", "no se admite")), (path, line)
                assert not re.search(re.escape(variable) + r"[` ]*\s*=", line), (path, line)


def test_entrypoint_rejects_unsafe_values():
    common_environment = [
        "-e",
        "CASHFUSION_ENABLED=true",
    ]
    result = run(
        [
            "docker",
            "run",
            "--rm",
            *common_environment,
            "-e",
            "USE_TOR=invalid",
            IMAGE,
        ]
    )
    assert result.returncode == 1
    assert "USE_TOR" in result.stdout


def test_entrypoint_rejects_missing_tor_setting():
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "CASHFUSION_ENABLED=true",
            IMAGE,
        ]
    )
    assert result.returncode == 1
    assert "USE_TOR must be set" in result.stdout + result.stderr


def test_entrypoint_rejects_missing_volume():
    result = run(
        [
            "docker",
            "run",
            "--rm",
            "-e",
            "USE_TOR=true",
            IMAGE,
        ]
    )
    assert result.returncode == 1
    assert "mounted Docker volume" in result.stdout


def test_test_wallet_password_hook():
    code = r'''
import importlib.util
import json

from electroncash.daemon import Daemon

spec = importlib.util.spec_from_file_location(
    "electroncash_wrapper", "/home/electroncash/electroncash-wrapper.py"
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
    with disposable_volume("cashfusion-password") as volume:
        output = docker_python(
            volume,
            code,
            env={"NETWORK": "chipnet", "TEST_WALLET_PASSWORD": PASSWORD},
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
            "CASHFUSION_ENABLED=true",
            "-e",
            "TEST_WALLET_PASSWORD=test-only",
            IMAGE,
        ]
    )
    assert result.returncode == 1
    output = result.stdout + result.stderr
    assert "require NETWORK=chipnet" in output, output


def main():
    test_public_defaults()
    test_removed_cashfusion_environment_is_absent_from_public_surfaces()
    test_invalid_values()
    test_invalid_config_is_preserved()
    test_compose_cashfusion_environment()
    test_wallet_lifecycle()
    test_gui_change_survives_default_restart()
    test_auto_fuse_later_uses_persisted_target_count()
    test_disable_restart_reenable_preserves_gui_choice()
    test_entrypoint_rejects_unsafe_values()
    test_entrypoint_rejects_missing_tor_setting()
    test_entrypoint_rejects_missing_volume()
    test_test_wallet_password_hook()
    test_mainnet_rejects_test_password()

    preserved = {
        "cashfusion_autofuse": False,
        "cashfusion_fusion_mode": "normal",
        "cashfusion_fuse_depth": 7,
        "cashfusion_self_fuse_players": 2,
        "cashfusion_selector": ["count", 20],
        "cashfusion_queued_autofuse": 2,
        "cashfusion_autofuse_only_when_all_confirmed": False,
    }
    preserved_autofuse = dict(preserved)
    preserved_autofuse["cashfusion_autofuse"] = True
    for encrypted in (False, True):
        for enabled, settings, overrides, label in (
            (False, None, None, "disabled"),
            (
                False,
                None,
                {"CASHFUSION_AUTO_FUSE": "true"},
                "disabled-autofuse-override",
            ),
            (True, None, None, "enabled-manual-default"),
            (
                True,
                None,
                {"CASHFUSION_AUTO_FUSE": "true"},
                "enabled-autofuse",
            ),
            (True, preserved, None, "preserved-false"),
            (
                True,
                preserved,
                {"CASHFUSION_AUTO_FUSE": "true"},
                "preserved-false-overrides-autofuse",
            ),
            (True, preserved_autofuse, None, "preserved-true"),
        ):
            test_state(encrypted, enabled, settings, overrides)
            storage = "encrypted" if encrypted else "plaintext"
            print(f"PASS {storage}: {label}")

    for selector_overrides, expected_selector in (
        (
            {
                "CASHFUSION_SELECTOR_MODE": "size",
                "CASHFUSION_SELECTOR_SIZE_BCH": "0.001",
            },
            ["size", 100000],
        ),
        (
            {
                "CASHFUSION_SELECTOR_MODE": "fraction",
                "CASHFUSION_SELECTOR_FRACTION": "0.5",
            },
            ["fraction", 0.5],
        ),
    ):
        test_state(False, True, overrides=selector_overrides)
        print(f"PASS plaintext: selector {expected_selector!r}")

    for existing_selector, selector_overrides in (
        (
            ["size", 10000],
            {
                "CASHFUSION_SELECTOR_MODE": "fraction",
                "CASHFUSION_SELECTOR_FRACTION": "0.5",
            },
        ),
        (
            ["fraction", 0.5],
            {
                "CASHFUSION_SELECTOR_MODE": "count",
                "CASHFUSION_SELECTOR_COUNT": "25",
            },
        ),
    ):
        existing = dict(preserved)
        existing["cashfusion_selector"] = existing_selector
        test_state(False, True, existing, selector_overrides)
        print(f"PASS plaintext: preserved selector {existing_selector!r}")

    print(
        "PASS invalid gate, atomic config guard, public defaults, unsafe "
        "entrypoint values, and test-password guards"
    )


if __name__ == "__main__":
    main()
