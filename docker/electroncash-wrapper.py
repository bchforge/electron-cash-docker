#!/opt/electroncash-venv/bin/python

import os
import runpy
import signal
import sys
from functools import wraps
from pathlib import Path


APP_PATH = "/opt/electroncash-venv/bin/electron-cash"
SHUTDOWN_MARKER = Path("/tmp/electron-cash-shutdown")
_shutdown_requested = False
_shutdown_started = False


def request_shutdown(_signum, _frame):
    global _shutdown_requested
    _shutdown_requested = True


def install_shutdown_timer():
    from electroncash_gui.qt import ElectrumGui
    from PyQt5.QtCore import QTimer

    original_main = ElectrumGui.main

    def main(gui):
        timer = QTimer(gui)
        windows_maximized = False

        def poll_shutdown():
            nonlocal windows_maximized
            global _shutdown_started

            if not windows_maximized and gui.windows:
                for window in gui.windows:
                    window.showMaximized()
                windows_maximized = True

            if (_shutdown_requested or SHUTDOWN_MARKER.exists()) and not _shutdown_started:
                _shutdown_started = True
                gui.close()
                gui.app.quit()

        timer.timeout.connect(poll_shutdown)
        timer.start(100)
        gui._shutdown_timer = timer
        return original_main(gui)

    ElectrumGui.main = main


def apply_cashfusion_autofuse(wallet, enabled, auto_fuse):
    if not enabled:
        return False

    from electroncash_plugins.fusion.conf import Conf

    conf = Conf(wallet)
    if conf.autofuse == auto_fuse:
        return False

    conf.autofuse = auto_fuse
    wallet.storage.write()
    wallet.print_error(f"[fusion] environment autofuse set to {auto_fuse}")
    return True


def patch_cashfusion_plugin_class(plugin_class, enabled, auto_fuse, test_password=""):
    if getattr(plugin_class, "_docker_autofuse_patched", False):
        return

    original_on_new_window = plugin_class.on_new_window

    @wraps(original_on_new_window)
    def on_new_window(plugin, window):
        wallet = window.wallet
        if plugin.wallet_can_fuse(wallet):
            try:
                if test_password and wallet.has_password():
                    wallet.check_password(test_password)
                    window.gui_object.cache_password(wallet, test_password)
                apply_cashfusion_autofuse(wallet, enabled, auto_fuse)
            except Exception as error:
                wallet.print_error(f"[fusion] failed to apply environment autofuse: {error}")
        return original_on_new_window(plugin, window)

    plugin_class.on_new_window = on_new_window
    plugin_class._docker_autofuse_patched = True


def install_cashfusion_autofuse():
    enabled = os.environ.get("CASHFUSION_ENABLED", "false") == "true"
    auto_fuse = os.environ.get("CASHFUSION_AUTO_FUSE", "false") == "true"
    test_password = os.environ.get("TEST_WALLET_PASSWORD", "")

    if not enabled:
        return

    from electroncash.plugins import BasePlugin

    original_init = BasePlugin.__init__

    def init(plugin, parent, config, name):
        if name == "fusion" and type(plugin).__module__ == "electroncash_plugins.fusion.qt":
            patch_cashfusion_plugin_class(type(plugin), enabled, auto_fuse, test_password)
        original_init(plugin, parent, config, name)

    BasePlugin.__init__ = init


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
        if wallet_password is None:
            wallet_password = password
        return original_load_wallet(daemon, path, wallet_password)

    Daemon.load_wallet = load_wallet


def main():
    signal.signal(signal.SIGTERM, request_shutdown)
    signal.signal(signal.SIGINT, request_shutdown)
    install_shutdown_timer()
    install_test_wallet_password()
    install_cashfusion_autofuse()
    sys.argv[0] = APP_PATH
    runpy.run_path(APP_PATH, run_name="__main__")


if __name__ == "__main__":
    main()
