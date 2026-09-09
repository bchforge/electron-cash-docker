"""Shared deployment-controlled CashFusion wallet configuration."""


def apply_cashfusion_autofuse(wallet, enabled, auto_fuse):
    if not enabled:
        return False

    from electroncash_plugins.fusion.conf import Conf

    conf = Conf(wallet)
    desired = bool(auto_fuse)
    if conf.autofuse == desired:
        return False

    conf.autofuse = desired
    wallet.storage.write()
    wallet.print_error(f"[fusion] environment autofuse set to {desired}")
    return True
