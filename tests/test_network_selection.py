#!/usr/bin/env python3
"""Single-authority selection and upstream pin coherence."""
import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docker"))
from network_selection import NETWORK_FLAGS, NetworkSelectionError, custom_args, effective_network, network_directory, network_from_compose, network_from_environment_document


def main():
    expected = {"mainnet": "", "testnet": "--testnet", "testnet4": "--testnet4",
                "scalenet": "--scalenet", "chipnet": "--chipnet", "regtest": "--regtest"}
    assert NETWORK_FLAGS == expected
    assert effective_network({}) == "mainnet"
    for network, flag in expected.items():
        assert effective_network({"NETWORK": network, "CHIPNET": "false", "TESTNET4": "false"}) == network
        assert network_directory(network) == "/home/electroncash/.electron-cash" + (f"/{network}" if flag else "")
        assert network_from_compose({"services": {"electron-cash": {"environment": {"NETWORK": network}}}}) == network
        assert network_from_environment_document([f"NETWORK={network}"]) == network
    for values, message in [({"NETWORK": ""}, "invalid NETWORK"),
                            ({"NETWORK": "CHIPNET"}, "invalid NETWORK"),
                            ({"CHIPNET": "true"}, "NETWORK=<network>"),
                            ({"TESTNET4": "true"}, "NETWORK=<network>"),
                            ({"CHIPNET": "True"}, "CHIPNET must"),
                            ({"NETWORK": "chipnet", "ELECTRONCASH_ARGS": "--testnet"}, "reserved"),
                            ({"NETWORK": "testnet", "ELECTRONCASH_ARGS": "--chipnet=1"}, "reserved"),
                            ({"ELECTRONCASH_ARGS": "--portable"}, "reserved"),
                            ({"ELECTRONCASH_ARGS": "--electron_cash_path=/tmp/elsewhere"}, "reserved")]:
        try:
            effective_network(values)
        except NetworkSelectionError as error:
            assert message in str(error), (values, error)
        else:
            raise AssertionError(f"accepted conflicting selection: {values}")
    assert custom_args('--verbose --foo "bar baz"') == ["--verbose", "--foo", "bar baz"]
    for filename in ("electroncash-wrapper.py", "electroncash-daemon-wrapper.py"):
        path = ROOT / "docker" / filename
        spec = importlib.util.spec_from_file_location(filename.replace("-", "_"), path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        previous = os.environ.copy()
        try:
            os.environ.update(NETWORK="mainnet", TEST_WALLET_PASSWORD="synthetic-only")
            try:
                module.install_test_wallet_password()
            except RuntimeError as error:
                assert "NETWORK=chipnet" in str(error)
            else:
                raise AssertionError("test password accepted for mainnet")
        finally:
            os.environ.clear()
            os.environ.update(previous)
    print("PASS six pinned networks, one selector, path isolation and reserved arguments")


if __name__ == "__main__":
    main()
