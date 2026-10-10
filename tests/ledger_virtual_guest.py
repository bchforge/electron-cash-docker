"""Test-only APDU transport; executed inside the unchanged current wallet image.

The transport replaces only LedgerPlugin.get_btchip_device. No Ledger command,
initialization, xpub or transaction method is replaced. This PUBLIC BIP39 fixture
must never receive funds or be used as a real wallet.
"""
import hashlib
import hmac
import inspect
import json
import os
import socket
import struct
import sys
from types import SimpleNamespace
from unittest.mock import patch

import ecdsa
import electroncash_plugins.ledger.ledger as ledger
from btchip.btchipException import BTChipException
from electroncash.address import Address
from electroncash.simple_config import SimpleConfig

MNEMONIC = "abandon " * 11 + "about"
ACCOUNT = "m/44'/145'/0'"
LEAF = ACCOUNT + "/0/0"
PLUGIN_SHA256 = "46882b2ab008063555bfebf3ffef7fda9e0a825693a35a4da9b3f5223e25b30b"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def hash160(value):
    return hashlib.new("ripemd160", hashlib.sha256(value).digest()).digest()


def public(secret):
    point = ecdsa.SigningKey.from_secret_exponent(secret, curve=ecdsa.SECP256k1).verifying_key.pubkey.point
    return bytes([2 + point.y() % 2]) + point.x().to_bytes(32, "big")


def base58check(payload):
    raw = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number = int.from_bytes(raw, "big")
    result = ""
    while number:
        number, remainder = divmod(number, 58)
        result = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[remainder] + result
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + result


def cashaddr(payload):
    # Independent CashAddr P2PKH version 0, 160-bit hash, prefix bitcoincash.
    words, accumulator, bits = [], 0, 0
    for value in b"\0" + payload:
        accumulator = (accumulator << 8) | value
        bits += 8
        while bits >= 5:
            bits -= 5
            words.append((accumulator >> bits) & 31)
    if bits:
        words.append((accumulator << (5 - bits)) & 31)
    checksum = 1
    for value in [ord(c) & 31 for c in "bitcoincash"] + [0] + words + [0] * 8:
        top = checksum >> 35
        checksum = ((checksum & 0x7ffffffff) << 5) ^ value
        for i, generator in enumerate((0x98f2bc8e61, 0x79b76d99e2, 0xf33e5fb3c4, 0xae2eabe2a8, 0x1e4f43e470)):
            if top & (1 << i):
                checksum ^= generator
    checksum ^= 1
    return "bitcoincash:" + "".join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[v] for v in
        words + [(checksum >> (5 * (7 - i))) & 31 for i in range(8)])


def expected(path):
    # BIP39 PBKDF2 + BIP32 CKDpriv independently of Electron Cash's bitcoin module.
    seed = hashlib.pbkdf2_hmac("sha512", MNEMONIC.encode(), b"mnemonic", 2048)
    material = hmac.new(b"Bitcoin seed", seed, "sha512").digest()
    secret, chain = int.from_bytes(material[:32], "big"), material[32:]
    fingerprint = b"\0" * 4
    indexes = [int(v.rstrip("'")) | (0x80000000 if v.endswith("'") else 0) for v in path.split("/")[1:]]
    for index in indexes:
        fingerprint = hash160(public(secret))[:4]
        data = b"\0" + secret.to_bytes(32, "big") if index & 0x80000000 else public(secret)
        material = hmac.new(chain, data + struct.pack(">I", index), "sha512").digest()
        require(int.from_bytes(material[:32], "big") < ecdsa.SECP256k1.order, "invalid fixture child")
        secret = (secret + int.from_bytes(material[:32], "big")) % ecdsa.SECP256k1.order
        require(secret != 0, "zero fixture child")
        chain = material[32:]
    pub = public(secret)
    xpub = base58check(bytes.fromhex("0488b21e") + bytes([len(indexes)]) + fingerprint +
                      struct.pack(">I", indexes[-1]) + chain + pub)
    return {"path": path, "public_key": pub.hex(), "chain_code": chain.hex(), "xpub": xpub,
            "legacy_address": base58check(b"\0" + hash160(pub)), "cashaddr": cashaddr(hash160(pub))}


class SpeculosTransport:
    def __init__(self, host, transcript):
        self.socket = socket.create_connection((host, 9999), timeout=15)
        self.socket.settimeout(30)
        self.transcript = transcript
        self.closed = False

    def receive(self, count):
        result = b""
        while len(result) < count:
            chunk = self.socket.recv(count - len(result))
            require(bool(chunk), "Speculos disconnected during APDU")
            result += chunk
        return result

    def exchange(self, command, timeout=30):
        self.socket.settimeout(timeout)
        command = bytes(command)
        self.socket.sendall(struct.pack(">I", len(command)) + command)
        length = struct.unpack(">I", self.receive(4))[0]
        require(length <= 65536, "unbounded Speculos response")
        # Speculos TCP length excludes the two status bytes.
        response = self.receive(length + 2)
        status = int.from_bytes(response[-2:], "big")
        self.transcript.append({"command": command.hex(), "response": response.hex(), "status": f"{status:04x}"})
        if status != 0x9000:
            raise BTChipException("Speculos status", status)
        return bytearray(response[:-2])

    def close(self):
        self.socket.close()
        self.closed = True


def main():
    require(os.getuid() == 10001, "wallet process must be non-root")
    require(ledger.LedgerPlugin.libraries_available, "real Ledger dependencies unavailable")
    if ledger.__file__ is None:
        raise RuntimeError("plugin source path missing")
    with open(ledger.__file__, "rb") as source:
        plugin_hash = hashlib.sha256(source.read()).hexdigest()
    require(plugin_hash == PLUGIN_SHA256, "bundled Ledger plugin differs from pinned Electron Cash 4.4.6")
    config = SimpleConfig({"electron_cash_path": "/tmp/ledger-wallet"})
    parent = SimpleNamespace(daemon_commands={}, device_manager=SimpleNamespace(register_devices=lambda _ids: None))
    plugin = ledger.LedgerPlugin(parent, config, "ledger")
    handler = SimpleNamespace()
    device = SimpleNamespace(product_key=(0x2c97, 0x4011), path=b"speculos-test-only",
                             interface_number=0, usage_page=0xffa0)
    transcript, transports, identities = [], [], []
    def transport(_plugin, _device):
        instance = SpeculosTransport(sys.argv[1], transcript)
        transports.append(instance)
        return instance
    account, leaf = expected(ACCOUNT), expected(LEAF)
    with patch.object(ledger.LedgerPlugin, "get_btchip_device", transport):
        for attempt in range(2):
            client = plugin.create_client(device, handler)
            client.handler = handler
            try:
                require(type(client) is ledger.Ledger_Client, "production client not used")
                client.checkDevice()
                require(client.preflightDone and client.supports_bitcoin_cash(), "BCH preflight failed")
                require(client.supports_cashaddr(), "BCH CashAddr not supported")
                require(client.has_usable_connection_with_device(), "device communication failed")
                actual = client.get_xpub(ACCOUNT, "standard")
                require(actual == account["xpub"], "account xpub mismatch")
                leaf_xpub = client.get_xpub(LEAF, "standard")
                require(leaf_xpub == leaf["xpub"], "leaf xpub mismatch")
                node = client.dongleObject.getWalletPublicKey(LEAF[2:], showOnScreen=False, cashAddr=True)
                pub = bytes(ledger.compress_public_key(node["publicKey"]))
                require(pub.hex() == leaf["public_key"], "public key mismatch")
                require(bytes(node["chainCode"]).hex() == leaf["chain_code"], "chain code mismatch")
                address = node["address"]
                if isinstance(address, bytes):
                    address = address.decode()
                expected_device_address = leaf["cashaddr"].split(":")[1]
                # btchip 0.1.32 does str(bytearray) on Python 3. Preserve the
                # real parser and compare its exact representation, too.
                require(address.removeprefix("bitcoincash:") == expected_device_address or
                        address == str(bytearray(expected_device_address.encode())),
                        "device CashAddr mismatch: " + repr(address) + " expected " + leaf["cashaddr"])
                require(Address.from_pubkey(pub).to_full_string(Address.FMT_CASHADDR) == leaf["cashaddr"], "Electron Cash address mismatch")
                identities.append({"account_xpub": actual, "leaf_xpub": leaf_xpub, "public_key": pub.hex(),
                                   "cashaddr": leaf["cashaddr"], "btchip_address": address,
                                   "firmware": client.dongleObject.getFirmwareVersion(),
                                   "preflight": "PASS"})
            finally:
                client.close()
    require(identities[0] == identities[1], "reconnect identity differs")
    require(len(transports) == 2 and all(t.closed for t in transports), "transport cleanup failed")
    instructions = {record["command"][2:4] for record in transcript}
    require({"c4", "24", "22", "40"}.issubset(instructions), "mandatory initialization/identity APDUs missing")
    print(json.dumps({"status": "PASS", "plugin": {"path": ledger.__file__,
        "sha256": plugin_hash, "electron_cash_version": "4.4.6",
        "electron_cash_commit": "9d500949b38dd181a986382eb0c2f6061b829fec",
        "client": ledger.Ledger_Client.__module__ + "." + ledger.Ledger_Client.__name__,
        "initialization": "PASS", "injection": "get_btchip_device transport only",
        "get_xpub_source_sha256": hashlib.sha256(inspect.getsource(ledger.Ledger_Client.get_xpub).encode()).hexdigest()},
        "derivation": {"status": "PASS", "expected_account": account, "expected_leaf": leaf,
                       "observed": identities[0], "oracle": "independent BIP39/BIP32 CKDpriv + ecdsa + Base58Check/CashAddr"},
        "reconnect": {"status": "PASS", "connections": 2, "identical": identities[0] == identities[1]},
        "transport": {"status": "PASS", "framing": "Speculos TCP length/APDU/status", "apdus": transcript,
                      "closed": all(t.closed for t in transports)}}))


if __name__ == "__main__":
    main()
