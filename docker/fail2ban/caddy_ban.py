#!/usr/bin/env python3
"""Reconcile typed Fail2Ban bans with Caddy and the namespace firewall.

The client identity map is written by caddy-log-adapter.  It is deliberately
separate from the authoritative ban state so a proxy visitor can be blocked
in Caddy without ever turning a shared proxy peer into a packet DROP.
"""

from __future__ import annotations

import fcntl
import http.client
import ipaddress
import json
import logging
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, NoReturn


STATE_DIR = Path(os.environ.get("CADDY_BAN_STATE_DIR", "/var/lib/caddy-bans"))
STATE_FILE = STATE_DIR / "banlist.json"
SNIPPET_FILE = STATE_DIR / "banlist.caddy"
CADDYFILE = STATE_DIR / "Caddyfile"
IDENTITY_FILE = STATE_DIR / "client-identity.json"
FAILURE_FILE = STATE_DIR / "protection-error.json"
LOCK_FILE = STATE_DIR / ".lock"
ADMIN_SOCKET = os.environ.get("CADDY_ADMIN_SOCKET", "/run/caddy/admin.sock")
FIREWALL_CHAIN = "ECD_FAIL2BAN"
INGRESS_PORTS = "80,443"
STATE_VERSION = 1
logger = logging.getLogger("caddy-ban")
logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")


class ReconcileError(RuntimeError):
    """A reconcile failed, including when rollback could not complete."""


def fail(message: str) -> NoReturn:
    logger.error(message)
    raise SystemExit(f"caddy-ban: {message}")


def validate_ip(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as error:
        fail(f"invalid ban address: {value}")
        raise AssertionError from error


def sort_ip(value: str) -> tuple[int, int]:
    address = ipaddress.ip_address(value)
    return address.version, int(address)


def _validate_entry(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        fail("ban state entry is not an object")
    client_ip = validate_ip(str(value.get("client_ip", "")))
    mode = value.get("mode")
    if mode not in {"direct", "trusted_proxy", "collapsed"}:
        fail(f"invalid ban mode for {client_ip}")
    peer = value.get("peer_ip")
    peer_ip = validate_ip(str(peer)) if peer is not None else None
    packet_drop = value.get("packet_drop")
    if not isinstance(packet_drop, bool):
        fail(f"invalid packet-drop flag for {client_ip}")
    if mode == "direct" and (not packet_drop or peer_ip != client_ip):
        fail(f"direct ban has unsafe packet identity for {client_ip}")
    if mode != "direct" and packet_drop:
        fail(f"non-direct ban requests packet DROP for {client_ip}")
    normalized = {
        "client_ip": client_ip,
        "peer_ip": peer_ip,
        "mode": mode,
        "packet_drop": packet_drop,
    }
    return normalized


def load_bans() -> list[dict[str, Any]]:
    if not STATE_FILE.exists():
        return []
    try:
        document = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"ban state is unreadable: {error}")
    if document == []:
        # The pre-v0.3 runtime used an empty JSON list. It contains no
        # identity that could be misclassified, so migrate it on the next
        # successful reconciliation; non-empty legacy state remains fail-closed.
        return []
    if not isinstance(document, dict) or document.get("version") != STATE_VERSION:
        fail("ban state has an unsupported schema")
    entries = document.get("bans")
    if not isinstance(entries, list):
        fail("ban state bans field is not a list")
    normalized = [_validate_entry(entry) for entry in entries]
    if len({entry["client_ip"] for entry in normalized}) != len(normalized):
        fail("ban state contains duplicate client identities")
    return sorted(normalized, key=lambda entry: sort_ip(entry["client_ip"]))


def _load_identity(address: str) -> dict[str, Any]:
    if not IDENTITY_FILE.exists():
        fail(f"no normalized client identity is available for {address}; refusing an ambiguous ban")
    try:
        document = json.loads(IDENTITY_FILE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        fail(f"client identity map is unreadable: {error}")
    if not isinstance(document, dict) or not isinstance(document.get(address), dict):
        fail(f"no normalized client identity is available for {address}; refusing an ambiguous ban")
    record = document[address]
    client_ip = validate_ip(str(record.get("client_ip", "")))
    if client_ip != address:
        fail(f"client identity map key does not match {address}")
    mode = record.get("mode")
    if mode not in {"direct", "trusted_proxy", "collapsed"}:
        fail(f"client identity map has invalid mode for {address}")
    if mode == "collapsed":
        fail(f"client identity for {address} is topology-collapsed; refusing an unsafe per-client ban")
    peer_value = record.get("peer_ip")
    peer_ip = validate_ip(str(peer_value)) if peer_value is not None else None
    packet_drop = record.get("packet_drop")
    if not isinstance(packet_drop, bool):
        fail(f"client identity map has invalid packet flag for {address}")
    if mode == "direct" and (not packet_drop or peer_ip != address):
        fail(f"direct client identity is not packet-safe for {address}")
    if mode != "direct" and packet_drop:
        fail(f"non-direct client identity requests packet DROP for {address}")
    return {"client_ip": address, "peer_ip": peer_ip, "mode": mode, "packet_drop": packet_drop}


def render_snippet(bans: list[dict[str, Any]]) -> str:
    identities = sorted({entry["client_ip"] for entry in bans}, key=sort_ip)
    if not identities:
        return "# No active Caddy client-IP bans.\n"
    return "@ecd_banned client_ip " + " ".join(identities) + "\nrespond @ecd_banned 403\n"


def _firewall_binary(address: str) -> str:
    return "/usr/sbin/iptables" if ipaddress.ip_address(address).version == 4 else "/usr/sbin/ip6tables"


def _firewall(binary: str, arguments: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    if not shutil.which(binary):
        fail(f"required packet-filter binary is unavailable: {binary}")
    result = subprocess.run(
        [binary, "-w", "5", *arguments],
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ReconcileError(f"firewall command failed: {binary} {' '.join(arguments)}: {detail}")
    return result


def _ensure_firewall_chain(binary: str) -> None:
    if _firewall(binary, ["-S", FIREWALL_CHAIN], check=False).returncode != 0:
        _firewall(binary, ["-N", FIREWALL_CHAIN])
    jumps = [
        line for line in _firewall(binary, ["-S", "INPUT"]).stdout.splitlines()
        if line.strip() == f"-A INPUT -j {FIREWALL_CHAIN}"
    ]
    while len(jumps) > 1:
        _firewall(binary, ["-D", "INPUT", "-j", FIREWALL_CHAIN])
        jumps.pop()
    if not jumps:
        _firewall(binary, ["-I", "INPUT", "1", "-j", FIREWALL_CHAIN])


def _installed_addresses(binary: str) -> set[str]:
    result = _firewall(binary, ["-S", FIREWALL_CHAIN])
    addresses: set[str] = set()
    for line in result.stdout.splitlines():
        fields = line.split()
        try:
            source = fields[fields.index("-s") + 1]
            action = fields[fields.index("-j") + 1]
            protocol = fields[fields.index("-p") + 1]
            ports = fields[fields.index("--dports") + 1]
            if protocol != "tcp" or ports != INGRESS_PORTS or action != "DROP":
                continue
            network = ipaddress.ip_network(source, strict=False)
        except (ValueError, IndexError):
            continue
        if network.prefixlen == network.max_prefixlen:
            addresses.add(str(network.network_address))
    return addresses


def _reconcile_firewall(bans: list[dict[str, Any]]) -> None:
    for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
        _ensure_firewall_chain(binary)
        desired = {
            entry["peer_ip"]
            for entry in bans
            if entry["packet_drop"] and entry["peer_ip"] is not None and _firewall_binary(entry["peer_ip"]) == binary
        }
        # ECD_FAIL2BAN is task-owned. Rebuilding only this chain makes stale and
        # duplicate rules deterministic without touching unrelated host rules.
        _firewall(binary, ["-F", FIREWALL_CHAIN])
        for address in sorted(desired, key=sort_ip):
            _firewall(
                binary,
                [
                    "-I",
                    FIREWALL_CHAIN,
                    "1",
                    "-s",
                    address,
                    "-p",
                    "tcp",
                    "-m",
                    "multiport",
                    "--dports",
                    INGRESS_PORTS,
                    "-j",
                    "DROP",
                ],
            )


def _check_firewall(bans: list[dict[str, Any]]) -> None:
    expected = {
        entry["peer_ip"]
        for entry in bans
        if entry["packet_drop"] and entry["peer_ip"] is not None
    }
    installed: set[str] = set()
    for binary in ("/usr/sbin/iptables", "/usr/sbin/ip6tables"):
        _ensure_firewall_chain(binary)
        installed.update(_installed_addresses(binary))
    if installed != expected:
        raise ReconcileError(
            "packet-filter state does not match authoritative direct-ban state: "
            f"installed={sorted(installed, key=sort_ip)} expected={sorted(expected, key=sort_ip)}"
        )


def atomic_write(path: Path, content: str, mode: int = 0o640) -> None:
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def _mark_failure(operation: str, error: BaseException, rollback_errors: list[str] | None = None) -> None:
    details = {
        "operation": operation,
        "error": str(error),
        "rollback_errors": rollback_errors or [],
    }
    try:
        atomic_write(FAILURE_FILE, json.dumps(details, sort_keys=True) + "\n")
    except Exception as marker_error:
        logger.exception("unable to publish protection failure state: %s", marker_error)
    logger.error("protection operation failed: %s", json.dumps(details, sort_keys=True))


def _clear_failure() -> None:
    try:
        FAILURE_FILE.unlink(missing_ok=True)
    except OSError as error:
        raise ReconcileError(f"unable to clear stale protection failure state: {error}") from error


def admin_request(path: str, body: bytes | None = None, content_type: str | None = None) -> tuple[int, bytes]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(5)
    connection: http.client.HTTPConnection | None = None
    try:
        sock.connect(ADMIN_SOCKET)
        connection = http.client.HTTPConnection("localhost", timeout=5)
        connection.sock = sock
        headers = {"Host": "localhost"}
        if body is not None:
            headers["Content-Type"] = content_type or "application/json"
            headers["Content-Length"] = str(len(body))
        connection.request("POST" if body is not None else "GET", path, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, response.read()
    except (ConnectionError, OSError, http.client.HTTPException) as error:
        raise ReconcileError(f"Caddy admin API unavailable: {error}") from error
    finally:
        if connection is not None:
            connection.close()
        else:
            sock.close()


def load_caddyfile() -> None:
    try:
        caddyfile = CADDYFILE.read_bytes()
    except OSError as error:
        raise ReconcileError(f"cannot read generated Caddyfile: {error}") from error
    status, adapted = admin_request("/adapt", caddyfile, "text/caddyfile")
    if status != 200:
        raise ReconcileError(f"Caddy rejected candidate configuration ({status}): {adapted.decode(errors='replace')}")
    # /adapt is a validation probe. The current Caddy admin API wraps its
    # adapted response, so loading that wrapper directly is invalid. Let /load
    # perform the same Caddyfile adaptation from the original source.
    status, response = admin_request("/load", caddyfile, "text/caddyfile")
    if status < 200 or status >= 300:
        raise ReconcileError(f"Caddy failed to load candidate configuration ({status}): {response.decode(errors='replace')}")


def _state_payload(bans: list[dict[str, Any]]) -> str:
    return json.dumps({"version": STATE_VERSION, "bans": bans}, indent=2, sort_keys=True) + "\n"


def _rollback(old_bans: list[dict[str, Any]], old_state: str | None, old_snippet: str | None) -> list[str]:
    errors: list[str] = []
    try:
        if old_state is None:
            STATE_FILE.unlink(missing_ok=True)
        else:
            atomic_write(STATE_FILE, old_state)
    except Exception as error:
        errors.append(f"restore authoritative state: {error}")
    try:
        if old_snippet is None:
            SNIPPET_FILE.unlink(missing_ok=True)
        else:
            atomic_write(SNIPPET_FILE, old_snippet)
    except Exception as error:
        errors.append(f"restore Caddy snippet: {error}")
    try:
        _reconcile_firewall(old_bans)
    except Exception as error:
        errors.append(f"restore packet rules: {error}")
    try:
        load_caddyfile()
    except Exception as error:
        errors.append(f"restore Caddy configuration: {error}")
    return errors


def reconcile_locked(bans: list[dict[str, Any]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    old_bans = load_bans()
    old_state = STATE_FILE.read_text(encoding="utf-8") if STATE_FILE.exists() else None
    old_snippet = SNIPPET_FILE.read_text(encoding="utf-8") if SNIPPET_FILE.exists() else None
    try:
        atomic_write(SNIPPET_FILE, render_snippet(bans))
        _reconcile_firewall(bans)
        load_caddyfile()
        # Publish only once the packet and Caddy boundaries both accepted the
        # same candidate, so observers never see a Caddy-only transient ban.
        atomic_write(STATE_FILE, _state_payload(bans))
        _check_firewall(bans)
        _clear_failure()
    except Exception as error:
        rollback_errors = _rollback(old_bans, old_state, old_snippet)
        _mark_failure("reconcile", error, rollback_errors)
        detail = f"reconcile failed: {error}"
        if rollback_errors:
            detail += "; rollback failed: " + "; ".join(rollback_errors)
            raise ReconcileError(detail) from error
        raise ReconcileError(detail) from error


def with_lock(function, *args: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        function(*args)


def _check_caddy_state(bans: list[dict[str, Any]]) -> None:
    status, response = admin_request("/config/")
    if status != 200:
        raise ReconcileError(f"Caddy admin API returned HTTP {status}")
    for entry in bans:
        if entry["client_ip"].encode("ascii") not in response:
            raise ReconcileError(f"Caddy configuration is missing ban identity {entry['client_ip']}")


def command_check() -> None:
    if FAILURE_FILE.exists():
        fail("protection failure state is present")
    bans = load_bans()
    _check_caddy_state(bans)
    _check_firewall(bans)


def command_admin_check() -> None:
    status, response = admin_request("/config/")
    if status != 200:
        raise ReconcileError(f"Caddy admin API returned HTTP {status}: {response.decode(errors='replace')}")


def command_reconcile() -> None:
    with_lock(lambda: reconcile_locked(load_bans()))


def command_ban(value: str) -> None:
    address = validate_ip(value)

    def update() -> None:
        identity = _load_identity(address)
        bans = [entry for entry in load_bans() if entry["client_ip"] != address]
        bans.append(identity)
        reconcile_locked(sorted(bans, key=lambda entry: sort_ip(entry["client_ip"])))

    with_lock(update)


def command_unban(value: str) -> None:
    address = validate_ip(value)

    def update() -> None:
        bans = [entry for entry in load_bans() if entry["client_ip"] != address]
        reconcile_locked(bans)

    with_lock(update)


def main() -> int:
    if len(sys.argv) < 2:
        fail("usage: caddy-ban check|reconcile|ban IP|unban IP")
    command = sys.argv[1]
    try:
        if command == "check" and len(sys.argv) == 2:
            command_check()
        elif command == "admin-check" and len(sys.argv) == 2:
            command_admin_check()
        elif command == "reconcile" and len(sys.argv) == 2:
            command_reconcile()
        elif command in {"ban", "unban"} and len(sys.argv) == 3:
            (command_ban if command == "ban" else command_unban)(sys.argv[2])
        else:
            fail("usage: caddy-ban admin-check|check|reconcile|ban IP|unban IP")
    except SystemExit:
        raise
    except Exception as error:
        print(f"caddy-ban: {error}", file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
