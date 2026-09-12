#!/usr/bin/env python3
"""Negative and positive tests for CI Compose resource isolation."""

from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from compose_guard import UnsafeComposeModel, validate_resolved_model  # noqa: E402


def model(*, wallet: str, tor: str, network: str, image: str, external: bool = False, host: bool = False) -> dict:
    return {
        "name": "bchforge-v021-test",
        "services": {
            "electron-cash": {
                "image": image,
                "volumes": [{"type": "volume", "source": "electron-cash-data", "target": "/home/electroncash/.electron-cash"}],
                "networks": {"electron-network": None},
                **({"network_mode": "host"} if host else {}),
            },
            "tor-proxy": {
                "image": "bchforge/electron-cash-docker-tor-ci:run",
                "volumes": [{"type": "volume", "source": "tor-data", "target": "/var/lib/tor"}],
                "networks": {"electron-network": None},
            },
        },
        "volumes": {
            "electron-cash-data": {"name": wallet, "external": external},
            "tor-data": {"name": tor},
        },
        "networks": {"electron-network": {"name": network}},
    }


def validate(document: dict) -> None:
    validate_resolved_model(
        document,
        expected_ec_image="electron-cash-ci:run",
        expected_tor_image="bchforge/electron-cash-docker-tor-ci:run",
        expected_wallet_volume="bchforge-v021-test-wallet",
        expected_tor_volume="bchforge-v021-test-tor",
        expected_network="bchforge-v021-test-network",
        expected_project="bchforge-v021-test",
    )


def main() -> None:
    validate(
        model(
            wallet="bchforge-v021-test-wallet",
            tor="bchforge-v021-test-tor",
            network="bchforge-v021-test-network",
            image="electron-cash-ci:run",
        )
    )
    for broken in (
        model(
            wallet="bchforge-electron-cash-data",
            tor="bchforge-v021-test-tor",
            network="bchforge-v021-test-network",
            image="electron-cash-ci:run",
        ),
        model(
            wallet="bchforge-v021-test-wallet",
            tor="bchforge-v021-test-tor",
            network="bchforge-v021-test-network",
            image="electron-cash:4.4.6",
        ),
        model(
            wallet="bchforge-v021-test-wallet",
            tor="bchforge-v021-test-tor",
            network="bchforge-v021-test-network",
            image="electron-cash-ci:run",
            host=True,
        ),
    ):
        try:
            validate(broken)
        except UnsafeComposeModel:
            continue
        raise AssertionError("unsafe Compose model was accepted")
    print("PASS Compose isolation positive and negative checks")


if __name__ == "__main__":
    main()
