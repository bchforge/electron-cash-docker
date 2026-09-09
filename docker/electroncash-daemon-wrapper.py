#!/opt/electroncash-venv/bin/python

"""Run Electron Cash's daemon without importing the Qt wrapper."""

import os
import runpy
import signal
import sys
from functools import wraps


APP_PATH = "/opt/electroncash-venv/bin/electron-cash"


def request_shutdown(_signum, _frame):
    raise SystemExit(0)


def install_test_wallet_password():
    password = os.environ.get("TEST_WALLET_PASSWORD", "")
    if not password:
        return
    if os.environ.get("TESTNET4", "false") != "true":
        raise RuntimeError("TEST_WALLET_PASSWORD is testnet4-only")

    from electroncash.daemon import Daemon

    original_load_wallet = Daemon.load_wallet

    @wraps(original_load_wallet)
    def load_wallet(daemon, path, wallet_password):
        if not wallet_password:
            wallet_password = password
        return original_load_wallet(daemon, path, wallet_password)

    Daemon.load_wallet = load_wallet


def install_cashfusion_autofuse():
    enabled = os.environ.get("CASHFUSION_ENABLED", "false") == "true"
    auto_fuse = os.environ.get("CASHFUSION_AUTO_FUSE", "false") == "true"
    if not enabled:
        return

    from electroncash.daemon import Daemon
    from cashfusion_autofuse import apply_cashfusion_autofuse

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
            # Apply the deployment setting before the plugin reads it. The
            # password is only the one already accepted by Daemon.load_wallet.
            apply_cashfusion_autofuse(wallet, enabled, auto_fuse)
            if not getattr(wallet, "_docker_cashfusion_attached", False):
                plugin.add_wallet(wallet, wallet_password)
                wallet._docker_cashfusion_attached = True
        except Exception as error:
            wallet.print_error(f"[fusion] failed to apply environment autofuse: {error}")
        return wallet

    Daemon.load_wallet = load_wallet


def main():
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    install_test_wallet_password()
    install_cashfusion_autofuse()
    sys.argv[0] = APP_PATH
    runpy.run_path(APP_PATH, run_name="__main__")


if __name__ == "__main__":
    main()
