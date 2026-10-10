"""CashFusion environment parsing and missing-only wallet initialization."""

from __future__ import annotations

import os
import re
from collections.abc import Mapping
from decimal import Decimal, InvalidOperation


class CashFusionConfigurationError(ValueError):
    """Raised when a CashFusion environment value is not natively supported."""


# These defaults are the public ECD profile.  They are initial values only;
# Electron Cash remains authoritative after a wallet key exists.
CASHFUSION_ENV_DEFAULTS = {
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

# This is kept as a separately named profile so callers and documentation can
# inspect the canonical defaults without importing Electron Cash.
CASHFUSION_DEFAULT_PROFILE = {
    "cashfusion_autofuse": False,
    "cashfusion_fusion_mode": "custom",
    "cashfusion_fuse_depth": 3,
    "cashfusion_self_fuse_players": 1,
    "cashfusion_selector": ["count", 10],
    "cashfusion_queued_autofuse": 4,
    "cashfusion_autofuse_only_when_all_confirmed": True,
}

_CONF_PROPERTIES = {
    "cashfusion_autofuse": "autofuse",
    "cashfusion_fusion_mode": "fusion_mode",
    "cashfusion_fuse_depth": "fuse_depth",
    "cashfusion_self_fuse_players": "self_fuse_players",
    "cashfusion_selector": "selector",
    "cashfusion_queued_autofuse": "queued_autofuse",
    "cashfusion_autofuse_only_when_all_confirmed": "autofuse_confirmed_only",
}


def _wallet_key_is_persisted(storage, key: str) -> bool:
    """Distinguish an absent key from Electron Cash's native fallback value."""

    return key in storage.data


_VALID_FUSION_MODES = frozenset(("normal", "consolidate", "fan-out", "custom"))
_VALID_SELECTOR_MODES = frozenset(("count", "size", "fraction"))
_SATOSHIS_PER_BCH = Decimal("100000000")
_MIN_SELECTOR_SIZE_SATOSHIS = 10000
MAX_POLICY_SATOSHIS = 21000000 * 100000000


def _parse_satoshis(name, environment):
    raw = _environment_value(name, environment).strip()
    if not re.fullmatch(r'[0-9]+', raw):
        raise CashFusionConfigurationError(f'{name} must be a non-negative integer in satoshis')
    value = int(raw, 10)
    if value > MAX_POLICY_SATOSHIS:
        raise CashFusionConfigurationError(f'{name} exceeds {MAX_POLICY_SATOSHIS} satoshis')
    return value


def _environment_value(name: str, environment: Mapping[str, str]) -> str:
    return environment.get(name, CASHFUSION_ENV_DEFAULTS[name])


def _parse_bool(name: str, environment: Mapping[str, str]) -> bool:
    value = _environment_value(name, environment).strip().lower()
    if value == "true":
        return True
    if value == "false":
        return False
    raise CashFusionConfigurationError(
        f"{name} must be true or false (got {value!r})"
    )


def _parse_int(
    name: str,
    environment: Mapping[str, str],
    minimum: int,
    maximum: int,
) -> int:
    raw_value = _environment_value(name, environment).strip()
    try:
        value = int(raw_value, 10)
    except (TypeError, ValueError) as error:
        raise CashFusionConfigurationError(
            f"{name} must be an integer (got {raw_value!r})"
        ) from error
    if not minimum <= value <= maximum:
        raise CashFusionConfigurationError(
            f"{name} must be between {minimum} and {maximum} "
            f"for Electron Cash 4.4.6 (got {value})"
        )
    return value


def _parse_decimal(name: str, environment: Mapping[str, str]) -> Decimal:
    raw_value = _environment_value(name, environment).strip()
    try:
        value = Decimal(raw_value)
    except (InvalidOperation, ValueError) as error:
        raise CashFusionConfigurationError(
            f"{name} must be a decimal number (got {raw_value!r})"
        ) from error
    if not value.is_finite():
        raise CashFusionConfigurationError(
            f"{name} must be a finite decimal number (got {raw_value!r})"
        )
    return value


def _parse_selector(environment: Mapping[str, str]) -> list:
    selector_mode = _environment_value(
        "CASHFUSION_SELECTOR_MODE", environment
    ).strip().lower()
    if selector_mode not in _VALID_SELECTOR_MODES:
        valid_modes = ", ".join(sorted(_VALID_SELECTOR_MODES))
        raise CashFusionConfigurationError(
            f"CASHFUSION_SELECTOR_MODE must be one of {valid_modes} "
            f"(got {selector_mode!r})"
        )

    if selector_mode == "count":
        selector_value = _parse_int(
            "CASHFUSION_SELECTOR_COUNT", environment, 10, 9999
        )
    elif selector_mode == "size":
        size_bch = _parse_decimal("CASHFUSION_SELECTOR_SIZE_BCH", environment)
        if size_bch <= 0:
            raise CashFusionConfigurationError(
                "CASHFUSION_SELECTOR_SIZE_BCH must be greater than 0"
            )
        size_satoshis = size_bch * _SATOSHIS_PER_BCH
        if size_satoshis != size_satoshis.to_integral_value():
            raise CashFusionConfigurationError(
                "CASHFUSION_SELECTOR_SIZE_BCH must have at most 8 decimal places"
            )
        selector_value = int(size_satoshis)
        if selector_value < _MIN_SELECTOR_SIZE_SATOSHIS:
            raise CashFusionConfigurationError(
                "CASHFUSION_SELECTOR_SIZE_BCH must be at least 0.0001 "
                "BCH (10000 satoshis) for Electron Cash"
            )
    else:
        fraction = _parse_decimal("CASHFUSION_SELECTOR_FRACTION", environment)
        if not Decimal("0") <= fraction <= Decimal("1"):
            raise CashFusionConfigurationError(
                "CASHFUSION_SELECTOR_FRACTION must be between 0.0 and 1.0"
            )
        selector_value = float(fraction)

    return [selector_mode, selector_value]


def cashfusion_config_from_environment(environment=None) -> dict:
    """Parse the CashFusion feature gate and initial wallet profile.

    The selector is represented using Electron Cash's native tuple shape:
    ``(mode, value)``.  Size values are converted from BCH to satoshis using
    decimal arithmetic before they are stored.
    """

    environment = os.environ if environment is None else environment
    fusion_mode = _environment_value("CASHFUSION_FUSION_MODE", environment).strip().lower()
    if fusion_mode not in _VALID_FUSION_MODES:
        valid_modes = ", ".join(sorted(_VALID_FUSION_MODES))
        raise CashFusionConfigurationError(
            f"CASHFUSION_FUSION_MODE must be one of {valid_modes} "
            f"(got {fusion_mode!r})"
        )

    profile = {
        "cashfusion_autofuse": _parse_bool("CASHFUSION_AUTO_FUSE", environment),
        "cashfusion_fusion_mode": fusion_mode,
        "cashfusion_fuse_depth": _parse_int(
            "CASHFUSION_FUSE_DEPTH", environment, 0, 10
        ),
        "cashfusion_self_fuse_players": _parse_int(
            "CASHFUSION_SELF_FUSE_PLAYERS", environment, 1, 2
        ),
        "cashfusion_selector": _parse_selector(environment),
        "cashfusion_queued_autofuse": _parse_int(
            "CASHFUSION_QUEUED_AUTOFUSE", environment, 1, 10
        ),
        "cashfusion_autofuse_only_when_all_confirmed": _parse_bool(
            "CASHFUSION_AUTOFUSE_CONFIRMED_ONLY", environment
        ),
    }
    return {
        "enabled": _parse_bool("CASHFUSION_ENABLED", environment),
        "profile": profile,
        "limits": {
            "fee_budget_satoshis": _parse_satoshis("CASHFUSION_FEE_BUDGET", environment),
            "minimum_input_satoshis": _parse_satoshis("CASHFUSION_MIN_UTXO", environment),
        },
    }


def apply_cashfusion_defaults(wallet, profile=None) -> bool:
    """Persist initial values only for native keys missing from a wallet."""

    from electroncash_plugins.fusion.conf import Conf

    if profile is None:
        profile = cashfusion_config_from_environment()["profile"]

    storage = wallet.storage
    conf = Conf(wallet)
    changed = False
    for key, value in profile.items():
        # Conf getters return Electron Cash defaults for absent keys. Inspect
        # the raw WalletStorage data so those library fallbacks do not block
        # the ECD-owned initial profile, while persisted user values remain
        # authoritative.
        if _wallet_key_is_persisted(storage, key):
            continue
        setattr(conf, _CONF_PROPERTIES[key], value)
        changed = True
    if changed:
        storage.write()
    return changed
