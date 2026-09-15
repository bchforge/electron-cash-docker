#!/usr/bin/env python3
"""Exercise the native ECC boundary and fail-closed fallback behavior."""

from __future__ import annotations

import os
import subprocess

from test_support import electron_cash_image


IMAGE = electron_cash_image()
PYTHON = "/opt/electroncash-venv/bin/python"


def run_python(code: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "docker",
            "run",
            "--pull=never",
            "--rm",
            "--network",
            "none",
            "--entrypoint",
            PYTHON,
            IMAGE,
            "-c",
            code,
        ],
        env=os.environ.copy(),
        text=True,
        capture_output=True,
        check=False,
        timeout=180,
    )


def test_native_private_operations_are_observed() -> None:
    result = run_python(
        r'''
import hashlib
import json

from electroncash import bitcoin, schnorr, secp256k1, ecc_fast
from electroncash_plugins.fusion import encrypt as fusion_encrypt

assert secp256k1.secp256k1 is not None
assert ecc_fast.is_using_fast_ecc()
events = []
library = secp256k1.secp256k1

def observe(name, function):
    def wrapper(*args):
        events.append(name)
        return function(*args)
    return wrapper

library.secp256k1_ecdsa_sign = observe(
    "ecdsa_sign", library.secp256k1_ecdsa_sign
)
library.secp256k1_ec_pubkey_tweak_mul = observe(
    "tweak_mul", library.secp256k1_ec_pubkey_tweak_mul
)
schnorr._secp256k1_schnorr_sign = observe(
    "schnorr_sign", schnorr._secp256k1_schnorr_sign
)

secret = b"\x01" * 32
message_hash = hashlib.sha256(b"synthetic-cve-control").digest()
key = bitcoin.regenerate_key(secret)
public_key = bitcoin.public_key_from_private_key(secret, True)
assert len(key.sign(message_hash)) == 64
assert bitcoin.encrypt_message(b"synthetic-ecdh", public_key)
ciphertext = fusion_encrypt.encrypt(b"synthetic-fusion", bytes.fromhex(public_key))
assert fusion_encrypt.decrypt(ciphertext, secret)[0] == b"synthetic-fusion"
assert len(schnorr.sign(secret, message_hash)) == 64

required = {"ecdsa_sign", "tweak_mul", "schnorr_sign"}
assert required.issubset(events), (required, events)
print(json.dumps({"observer": "native-backend", "events": events}))
'''
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert '"observer": "native-backend"' in result.stdout
    assert "ecdsa_sign" in result.stdout
    assert "tweak_mul" in result.stdout
    assert "schnorr_sign" in result.stdout


def test_missing_backend_fails_closed_before_application_initialization() -> None:
    result = run_python(
        r'''
import ctypes

def unavailable(_path):
    raise OSError("synthetic missing libsecp256k1")

ctypes.cdll.LoadLibrary = unavailable
try:
    import electroncash.bitcoin  # noqa: F401
except RuntimeError as error:
    assert "pure-python ecdsa private-operation fallback" in str(error)
    print("CONTROL missing-backend exercised: fail-closed")
else:
    raise AssertionError("Electron Cash initialized without libsecp256k1")
'''
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CONTROL missing-backend exercised: fail-closed" in result.stdout


def test_unusable_backend_and_schnorr_capability_fail_closed() -> None:
    unusable = run_python(
        r'''
import ctypes

ctypes.cdll.LoadLibrary = lambda _path: object()
try:
    import electroncash.bitcoin  # noqa: F401
except RuntimeError as error:
    assert "pure-python ecdsa private-operation fallback" in str(error)
    print("CONTROL unusable-backend exercised: fail-closed")
else:
    raise AssertionError("Electron Cash initialized with unusable libsecp256k1")
'''
    )
    assert unusable.returncode == 0, unusable.stdout + unusable.stderr
    assert "CONTROL unusable-backend exercised: fail-closed" in unusable.stdout

    schnorr_capability = run_python(
        r'''
import hashlib

from electroncash import schnorr

schnorr._secp256k1_schnorr_sign = None
try:
    schnorr.sign(b"\x01" * 32, hashlib.sha256(b"synthetic").digest())
except RuntimeError as error:
    assert "refusing the pure-python fallback" in str(error)
    print("CONTROL missing-Schnorr capability exercised: fail-closed")
else:
    raise AssertionError("Schnorr signing used its pure-python fallback")
'''
    )
    assert schnorr_capability.returncode == 0, (
        schnorr_capability.stdout + schnorr_capability.stderr
    )
    assert "CONTROL missing-Schnorr capability exercised: fail-closed" in schnorr_capability.stdout


def main() -> None:
    test_native_private_operations_are_observed()
    test_missing_backend_fails_closed_before_application_initialization()
    test_unusable_backend_and_schnorr_capability_fail_closed()
    print("PASS CVE-2024-23342 native dispatch and fail-closed fallback regression")


if __name__ == "__main__":
    main()
