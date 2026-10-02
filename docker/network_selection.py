"""Resolve Electron Cash's supported network selectors without guessing."""

from __future__ import annotations

import json
import os
import shlex
import sys
from collections.abc import Mapping


class NetworkSelectionError(ValueError):
    """Raised when the requested Electron Cash network is invalid or unsupported."""


# Electron Cash 4.4.6, commit 9d500949b38dd181a986382eb0c2f6061b829fec:
# electroncash/commands.py get_parser and electroncash/simple_config.py electrum_path.
NETWORK_FLAGS = {
    "mainnet": "",
    "testnet": "--testnet",
    "testnet4": "--testnet4",
    "scalenet": "--scalenet",
    "chipnet": "--chipnet",
    "regtest": "--regtest",
}
WALLET_ROOT = "/home/electroncash/.electron-cash"


def _selector(environment: Mapping[str, str | None], name: str) -> bool:
    value = environment.get(name)
    if value in (None, ""):
        return False
    if value == "true":
        return True
    if value == "false":
        return False
    raise NetworkSelectionError(f"{name} must be exactly true or false when set")


def effective_network(environment: Mapping[str, str | None] | None = None) -> str:
    """Validate the one public network selector before any state is touched."""
    values = os.environ if environment is None else environment
    for legacy in ("CHIPNET", "TESTNET4"):
        if _selector(values, legacy):
            raise NetworkSelectionError(f"{legacy}=true is obsolete; remove it and use NETWORK=<network>")
    network = values.get("NETWORK", "mainnet")
    if network not in NETWORK_FLAGS:
        raise NetworkSelectionError(
            f"invalid NETWORK={network!r}; use one of: {', '.join(NETWORK_FLAGS)}"
        )
    custom_args(values.get("ELECTRONCASH_ARGS", ""))
    return network


def custom_args(raw: str | None) -> list[str]:
    try:
        args = shlex.split(raw or "")
    except ValueError as error:
        raise NetworkSelectionError(f"invalid ELECTRONCASH_ARGS: {error}") from error
    reserved = {flag for flag in NETWORK_FLAGS.values() if flag} | {
        "--electron_cash_path", "--portable", "-P", "--wallet_path", "--wallet", "-w", "--dir", "-D",
    }
    for arg in args:
        if arg in reserved or any(arg.startswith(flag + "=") for flag in reserved):
            raise NetworkSelectionError(
                f"ELECTRONCASH_ARGS contains reserved selector/path {arg}; use NETWORK=<network>"
            )
    return args


def network_directory(network: str) -> str:
    if network not in NETWORK_FLAGS:
        raise NetworkSelectionError(f"unsupported backup network identity: {network}")
    return WALLET_ROOT if network == "mainnet" else f"{WALLET_ROOT}/{network}"


def network_from_compose(document: object) -> str:
    """Resolve the active network from Compose's fully merged service model."""
    if not isinstance(document, Mapping):
        raise NetworkSelectionError("resolved Compose model is invalid")
    services = document.get("services")
    service = services.get("electron-cash") if isinstance(services, Mapping) else None
    if not isinstance(service, Mapping):
        raise NetworkSelectionError("resolved Compose model has no electron-cash service")
    raw_environment = service.get("environment", {})
    if isinstance(raw_environment, Mapping):
        environment = {
            str(key): None if value is None else str(value)
            for key, value in raw_environment.items()
        }
    elif isinstance(raw_environment, list):
        environment = {}
        for entry in raw_environment:
            if not isinstance(entry, str) or "=" not in entry:
                raise NetworkSelectionError("resolved electron-cash environment is invalid")
            key, value = entry.split("=", 1)
            if key in environment:
                raise NetworkSelectionError("resolved electron-cash environment has duplicate keys")
            environment[key] = value
    else:
        raise NetworkSelectionError("resolved electron-cash environment is invalid")
    return effective_network(environment)


def network_from_environment_document(document: object) -> str:
    """Resolve network authority from Docker's serialized container Env list."""
    if isinstance(document, Mapping):
        environment = {str(key): None if value is None else str(value)
                       for key, value in document.items()}
    elif isinstance(document, list):
        environment = {}
        for entry in document:
            if not isinstance(entry, str) or "=" not in entry:
                raise NetworkSelectionError("container environment is invalid")
            key, value = entry.split("=", 1)
            if key in environment:
                raise NetworkSelectionError("container environment contains duplicate keys")
            environment[key] = value
    else:
        raise NetworkSelectionError("container environment is invalid")
    return effective_network(environment)


def main() -> int:
    try:
        if len(sys.argv) == 1:
            network = effective_network()
        elif sys.argv[1:] == ["--compose"]:
            network = network_from_compose(json.load(sys.stdin))
        elif sys.argv[1:] == ["--env-json"]:
            network = network_from_environment_document(json.load(sys.stdin))
        elif sys.argv[1:] == ["--details"]:
            network = effective_network()
            print(f"{network} {NETWORK_FLAGS[network] or '-'} {network_directory(network)}")
            return 0
        elif sys.argv[1:] == ["--args"]:
            effective_network()
            for arg in custom_args(os.environ.get("ELECTRONCASH_ARGS")):
                sys.stdout.buffer.write(arg.encode() + b"\0")
            return 0
        elif len(sys.argv) == 3 and sys.argv[1] == "--validate":
            network_directory(sys.argv[2])
            return 0
        else:
            print("usage: network_selection.py [--compose|--env-json|--details|--args|--validate NETWORK]", file=sys.stderr)
            return 2
        print(network)
    except (NetworkSelectionError, json.JSONDecodeError) as error:
        print(f"[!] {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
