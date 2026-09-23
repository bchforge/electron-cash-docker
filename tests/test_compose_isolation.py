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
                "expose": ["6080"],
                "networks": {"electron-network": None},
                **({"network_mode": "host"} if host else {}),
            },
            "tor-proxy": {
                "image": "bchforge/electron-cash-docker-tor-ci:run",
                "volumes": [{"type": "volume", "source": "tor-data", "target": "/var/lib/tor"}],
                "networks": {"electron-network": None},
            },
            "auth-session": {
                "image": "auth-session-ci:run",
                "environment": {
                    "BASIC_AUTH_PASSWORD": "synthetic-auth-secret",
                },
                "networks": {"electron-network": None},
                "cap_drop": ["ALL"],
            },
            "caddy": {
                "image": "caddy@sha256:test",
                "environment": {"AUTH_SESSION_UPSTREAM": "auth-session:8080"},
                "ports": [
                    {"target": 80, "published": "8080", "host_ip": "127.0.0.1", "protocol": "tcp"},
                    {"target": 443, "published": "8443", "host_ip": "127.0.0.1", "protocol": "tcp"},
                ],
                "volumes": [
                    {"type": "volume", "source": "caddy-data", "target": "/data"},
                    {"type": "volume", "source": "caddy-config", "target": "/config"},
                    {"type": "volume", "source": "caddy-log", "target": "/var/log/caddy"},
                    {"type": "volume", "source": "caddy-ban-state", "target": "/var/lib/caddy-bans"},
                    {"type": "volume", "source": "caddy-control", "target": "/run/caddy"},
                    {"type": "bind", "source": str(ROOT / "docker/caddy-entrypoint.sh"), "target": "/etc/caddy/entrypoint.sh", "read_only": True, "bind": {"create_host_path": False}},
                ],
                "networks": {"electron-network": None},
            },
            "fail2ban": {
                "image": "fail2ban-ci:run",
                "network_mode": "service:caddy",
                "cap_add": ["NET_ADMIN"],
                "cap_drop": ["ALL"],
                "volumes": [
                    {"type": "volume", "source": "caddy-log", "target": "/var/log/caddy", "read_only": True},
                    {"type": "volume", "source": "fail2ban-state", "target": "/var/lib/fail2ban"},
                    {"type": "volume", "source": "caddy-ban-state", "target": "/var/lib/caddy-bans"},
                    {"type": "volume", "source": "caddy-control", "target": "/run/caddy"},
                ],
            },
        },
        "volumes": {
            "electron-cash-data": {"name": wallet, "external": external},
            "tor-data": {"name": tor},
            "caddy-data": {"name": "bchforge-v021-test_caddy-data"},
            "caddy-config": {"name": "bchforge-v021-test_caddy-config"},
            "caddy-log": {"name": "bchforge-v021-test_caddy-log"},
            "fail2ban-state": {"name": "bchforge-v021-test_fail2ban-state"},
            "caddy-ban-state": {"name": "bchforge-v021-test_caddy-ban-state"},
            "caddy-control": {"name": "bchforge-v021-test_caddy-control"},
        },
        "networks": {"electron-network": {"name": network}},
    }


def validate(document: dict) -> None:
    validate_resolved_model(
        document,
        expected_ec_image="electron-cash-ci:run",
        expected_tor_image="bchforge/electron-cash-docker-tor-ci:run",
        expected_caddy_image="caddy@sha256:test",
        expected_fail2ban_image="fail2ban-ci:run",
        expected_auth_image="auth-session-ci:run",
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
    broken_https = model(
        wallet="bchforge-v021-test-wallet",
        tor="bchforge-v021-test-tor",
        network="bchforge-v021-test-network",
        image="electron-cash-ci:run",
    )
    broken_https["services"]["electron-cash"]["ports"] = [
        {"target": 6080, "published": "6080", "host_ip": "127.0.0.1", "protocol": "tcp"}
    ]
    try:
        validate(broken_https)
    except UnsafeComposeModel:
        pass
    else:
        raise AssertionError("model with direct noVNC publication was accepted")
    print("PASS Compose isolation positive and negative checks")


if __name__ == "__main__":
    main()
