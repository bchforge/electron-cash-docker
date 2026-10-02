#!/usr/bin/env python3
"""Safe Ledger image/backend and synthetic HID contract acceptance."""
import os
import json
import subprocess
from pathlib import Path

from test_support import ENV_DEFAULTS, electron_cash_image

PYTHON = "/opt/electroncash-venv/bin/python"
ROOT = Path(__file__).resolve().parents[1]


def run(arguments):
    try:
        return subprocess.run(arguments, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired as error:
        output = error.stdout or error.stderr or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        raise AssertionError(f"Ledger synthetic transport timed out; last checkpoint output: {output}") from error


def main():
    normal = electron_cash_image()
    hardware = os.environ.get("ECD_HW_IMAGE", f"electron-cash:{ENV_DEFAULTS['EC_VERSION']}-hw")
    ordinary = run(["docker", "run", "--rm", "--pull=never", "--network", "none",
                    "--user", "10001:10001", "--entrypoint", PYTHON, normal,
                    "-c", "import hid"])
    assert ordinary.returncode != 0 and "No module named 'hid'" in ordinary.stderr, ordinary.stderr
    script = """import os, hid
from electroncash_plugins.ledger.ledger import LedgerPlugin
assert os.getuid() == 10001 and LedgerPlugin.libraries_available
devices = hid.enumerate()
print('ledger-capable', os.getuid(), len(devices))
"""
    available = run(["docker", "run", "--rm", "--pull=never", "--network", "none",
                     "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                     "--user", "10001:10001", "-e", "PYTHONDONTWRITEBYTECODE=1",
                     "--entrypoint", PYTHON, hardware, "-c", script])
    assert available.returncode == 0, available.stderr
    assert available.stdout.startswith("ledger-capable 10001 ")
    fixture = json.loads((ROOT / "tests/fixtures/ledger/hid-contract.json").read_text())
    transport_test = r'''import json, os, sys, time
from types import SimpleNamespace
from unittest.mock import patch
import btchip.btchipComm as comm
from btchip.btchipException import BTChipException
from btchip.ledgerWrapper import wrapCommandAPDU
import electroncash_plugins.ledger.ledger as ledger

fixture = json.loads(sys.argv[1])
contract = fixture["transport"]
def checkpoint(name): print("ledger-transport-checkpoint", name, flush=True)
class FakeDevice:
    def __init__(self, reads=(), error=None): self.reads=list(reads); self.error=error; self.writes=[]; self.closed=False
    def open_path(self, path):
        if self.error: raise self.error
        self.path=path
    def set_nonblocking(self, value): self.nonblocking=value
    def write(self, value): self.writes.append(bytes(value)); return len(value)
    def read(self, _size):
        if self.error: raise self.error
        if self.reads: return bytes(self.reads.pop(0))
        return []
    def close(self): self.closed=True
class FakeHid:
    def __init__(self, device): self.device_instance=device
    def device(self): return self.device_instance
    def enumerate(self, *_args): return []

info=SimpleNamespace(product_key=(0x2c97,0x0001), interface_number=0, usage_page=0xffa0, path=b"synthetic")
plugin=SimpleNamespace(device="Ledger")
def backend(fake):
    ledger.hid=FakeHid(fake)
    return ledger.LedgerPlugin.get_btchip_device(plugin, info)
def framed(payload): return bytes(wrapCommandAPDU(0x0101, bytearray(payload), 64))
apdu=bytearray.fromhex("e0c4000000")

# The actual btchip discovery backend must fail closed when enumeration is empty.
old_hid, old_hid_flag, old_scard = comm.hid, comm.HID, comm.SCARD
try:
    checkpoint("empty-enumeration")
    comm.hid=FakeHid(FakeDevice()); comm.HID=True; comm.SCARD=False
    for name in ("LEDGER_PROXY_ADDRESS", "LEDGER_PROXY_PORT"): os.environ.pop(name, None)
    try: comm.getDongle()
    except BTChipException as error: assert "No dongle found" in str(error)
    else: raise AssertionError("missing device accepted")
finally:
    comm.hid, comm.HID, comm.SCARD=old_hid,old_hid_flag,old_scard
unsupported=SimpleNamespace(product_key=(0x2c97,0x0001),interface_number=2,usage_page=0x0001,path=b"unsupported-interface")
ledger.hid=FakeHid(FakeDevice())
checkpoint("unsupported-interface")
assert ledger.LedgerPlugin.get_btchip_device(plugin,unsupported) is None

# The production Electron Cash Ledger plugin constructs btchip's HID transport.
success_device=FakeDevice([framed(bytes.fromhex(contract["success_response_hex"]))])
checkpoint("success-exchange")
client=backend(success_device)
result=client.exchange(apdu)
assert bytes(result).hex()==contract["success_payload_hex"]
expected=bytes(wrapCommandAPDU(0x0101,apdu,64))
assert success_device.writes==[b"\x00"+expected]
client.close(); assert success_device.closed

for status, label in ((contract["cancel_status_hex"],"cancel"),(contract["unsupported_status_hex"],"unsupported")):
    checkpoint(label+"-status")
    device=FakeDevice([framed(bytes.fromhex(status))])
    instance=backend(device)
    try: instance.exchange(apdu)
    except BTChipException as error: assert error.sw==int(status,16), (label,error.sw)
    else: raise AssertionError(label+" status accepted")
    instance.close()

malformed=FakeDevice([bytes.fromhex(contract["malformed_channel_response_hex"])])
checkpoint("malformed-frame")
instance=backend(malformed)
try: instance.exchange(apdu)
except BTChipException as error: assert "Invalid channel" in str(error)
else: raise AssertionError("malformed channel accepted")

truncated=FakeDevice([bytes.fromhex(contract["truncated_response_hex"])], error=None)
checkpoint("truncated-frame")
class TruncatedDevice(FakeDevice):
    def __init__(self): super().__init__([bytes.fromhex(contract["truncated_response_hex"])]); self.calls=0
    def read(self, size):
        self.calls+=1
        if self.calls==1: return bytes(self.reads.pop(0))
        raise OSError("truncated HID frame")
truncated=TruncatedDevice(); instance=backend(truncated)
try: instance.exchange(apdu)
except OSError as error: assert "truncated" in str(error)
else: raise AssertionError("truncated response was accepted")

disconnected=FakeDevice(); instance=backend(disconnected)
disconnected.error=OSError("device disconnected")
checkpoint("disconnect")
try: instance.exchange(apdu)
except OSError as error: assert "disconnected" in str(error)
else: raise AssertionError("disconnect was accepted")

denied=FakeDevice(error=PermissionError("USB access denied"))
checkpoint("permission-denied")
try: backend(denied)
except PermissionError as error: assert "denied" in str(error)
else: raise AssertionError("permission error was suppressed")

timeout_device=FakeDevice()
checkpoint("timeout")
instance=backend(timeout_device)
ticks=[0]
def clock(): ticks[0]+=1; return ticks[0]
try:
    with patch.object(comm.time,"time",clock), patch.object(comm.time,"sleep",lambda _delay:None):
        try: instance.exchange(apdu,timeout=0)
        except BTChipException as error: assert "Timeout" in str(error)
        else: raise AssertionError("transport timeout was accepted")
finally: instance.close()

# Reconnect is a new production backend instance; no stale device is reused.
reconnected=FakeDevice([framed(bytes.fromhex(contract["success_response_hex"]))])
checkpoint("reconnect")
assert bytes(backend(reconnected).exchange(apdu)).hex()==contract["success_payload_hex"]
print("PASS synthetic production-HID APDU contracts: success, absent, denied, malformed, truncated, unsupported, cancellation, timeout, reconnect")'''
    transport = run(["docker", "run", "--pull=never", "--rm", "--network", "none",
                     "--read-only", "--cap-drop=ALL", "--security-opt", "no-new-privileges:true",
                     "--user", "10001:10001", "-e", "PYTHONDONTWRITEBYTECODE=1",
                     "--entrypoint", PYTHON, hardware, "-c", transport_test,
                     json.dumps(fixture, separators=(",", ":"))])
    assert transport.returncode == 0, transport.stdout + transport.stderr
    assert "synthetic production-HID APDU contracts" in transport.stdout
    print("PASS opt-in Ledger dependencies, non-root hardware image, normal image isolation and production-backend synthetic transport")


if __name__ == "__main__":
    main()
