#!/opt/electroncash-venv/bin/python

"""Run Electron Cash's daemon without importing the Qt wrapper."""

import os
import runpy
import signal
import sys
from functools import wraps

from network_selection import NetworkSelectionError, effective_network


APP_PATH = "/opt/electroncash-venv/bin/electron-cash"


def request_shutdown(_signum, _frame):
    raise SystemExit(0)


def install_test_wallet_password():
    password = os.environ.get("TEST_WALLET_PASSWORD", "")
    if not password:
        return
    try:
        network = effective_network()
    except NetworkSelectionError as error:
        raise RuntimeError(str(error)) from error
    if network != "chipnet":
        raise RuntimeError("TEST_WALLET_PASSWORD requires NETWORK=chipnet")

    from electroncash.daemon import Daemon

    original_load_wallet = Daemon.load_wallet

    @wraps(original_load_wallet)
    def load_wallet(daemon, path, wallet_password):
        if not wallet_password:
            wallet_password = password
        return original_load_wallet(daemon, path, wallet_password)

    Daemon.load_wallet = load_wallet


def install_cashfusion_defaults():
    from cashfusion_defaults import cashfusion_config_from_environment

    enabled = cashfusion_config_from_environment()["enabled"]
    if not enabled:
        return

    from electroncash.daemon import Daemon
    from cashfusion_defaults import apply_cashfusion_defaults

    original_load_wallet = Daemon.load_wallet

    @wraps(original_load_wallet)
    def load_wallet(daemon, path, wallet_password):
        wallet = original_load_wallet(daemon, path, wallet_password)
        if wallet is None:
            return None

        plugin = daemon.plugins.get_internal_plugin("fusion")
        if plugin is None or not plugin.wallet_can_fuse(wallet):
            return wallet

        try:
            apply_cashfusion_defaults(wallet)
            if not getattr(wallet, "_docker_cashfusion_attached", False):
                plugin.add_wallet(wallet, wallet_password)
                wallet._docker_cashfusion_attached = True
        except Exception as error:
            wallet.print_error(f"[fusion] failed to apply wallet defaults: {error}")
            raise RuntimeError("CashFusion deployment policy failed closed") from error
        return wallet

    Daemon.load_wallet = load_wallet


def main():
    try:
        effective_network()
    except NetworkSelectionError as error:
        print(f"[!] {error}", file=sys.stderr)
        raise SystemExit(1) from error
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    install_test_wallet_password()
    install_cashfusion_defaults()
    sys.argv[0] = APP_PATH
    runpy.run_path(APP_PATH, run_name="__main__")


if __name__ == "__main__":
    main()
