#!/usr/bin/env python3

from __future__ import annotations

import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import struct
import sys
import time
from pathlib import Path
import tempfile


raw_path = Path(os.environ.get("CADDY_ACCESS_LOG", "/var/log/caddy/access.log"))
parsed_path = Path(os.environ.get("FAIL2BAN_PARSED_LOG", "/var/lib/fail2ban/access.log"))
identity_path = Path(os.environ.get("CADDY_IDENTITY_MAP", "/var/lib/caddy-bans/client-identity.json"))
parsed_path.parent.mkdir(parents=True, exist_ok=True)
identity_path.parent.mkdir(parents=True, exist_ok=True)
logger = logging.getLogger("caddy-log-adapter")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler(parsed_path, maxBytes=10 * 1024 * 1024, backupCount=2)
handler.setFormatter(logging.Formatter("%(message)s"))
logger.addHandler(handler)


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


def namespace_gateways() -> set[IPAddress]:
    gateways: set[IPAddress] = set()
    try:
        for line in Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]:
            fields = line.split()
            if len(fields) >= 3 and fields[1] == "00000000":
                gateways.add(ipaddress.ip_address(struct.pack("<I", int(fields[2], 16))))
    except (OSError, ValueError):
        pass
    try:
        for line in Path("/proc/net/ipv6_route").read_text(encoding="ascii").splitlines():
            fields = line.split()
            if len(fields) >= 5 and fields[0] == "0" * 32 and fields[1] == "00000000":
                gateways.add(ipaddress.ip_address(int(fields[4], 16)))
    except (OSError, ValueError):
        pass
    return gateways


GATEWAYS = namespace_gateways()
TRUSTED_PROXY_FILE = Path(os.environ.get("CADDY_TRUSTED_PROXY_FILE", "/var/lib/caddy-bans/trusted-proxies.txt"))
malformed_lines = 0
topology_warnings = 0


def _trusted_networks() -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    if not TRUSTED_PROXY_FILE.exists():
        return ()
    try:
        values = []
        for line in TRUSTED_PROXY_FILE.read_text(encoding="ascii").splitlines():
            if line.strip():
                values.append(ipaddress.ip_network(line.strip(), strict=False))
        return tuple(values)
    except (OSError, UnicodeError, ValueError) as error:
        raise RuntimeError(f"trusted-proxy policy is unreadable: {error}") from error


def _in_trusted_proxy(address: IPAddress, networks: tuple) -> bool:
    return any(address.version == network.version and address in network for network in networks)


def _publish_identity(identity: str, record: dict[str, object]) -> None:
    try:
        current = json.loads(identity_path.read_text(encoding="utf-8")) if identity_path.exists() else {}
        if not isinstance(current, dict):
            raise RuntimeError("identity map is not an object")
        current[identity] = record
        fd, temporary = tempfile.mkstemp(prefix=".client-identity.", dir=identity_path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as output:
                json.dump(current, output, sort_keys=True, separators=(",", ":"))
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            os.chmod(temporary, 0o640)
            os.replace(temporary, identity_path)
        finally:
            Path(temporary).unlink(missing_ok=True)
    except (OSError, UnicodeError, json.JSONDecodeError, RuntimeError) as error:
        raise RuntimeError(f"cannot publish client identity state: {error}") from error


def _warn_malformed(message: str) -> None:
    global malformed_lines
    malformed_lines += 1
    if malformed_lines <= 5 or malformed_lines % 100 == 0:
        print(f"[!] caddy-log-adapter skipped malformed line {malformed_lines}: {message}", file=sys.stderr, flush=True)


def _warn_topology(message: str) -> None:
    global topology_warnings
    topology_warnings += 1
    if topology_warnings <= 5 or topology_warnings % 100 == 0:
        print(f"[!] caddy-log-adapter fail-closed topology event {topology_warnings}: {message}", file=sys.stderr, flush=True)


def process(line: str) -> None:
    try:
        record = json.loads(line)
        request = record.get("request") or {}
        remote = ipaddress.ip_address(request["remote_ip"])
        address = request.get("client_ip")
        status = int(record.get("status", 0))
        if status != 401:
            return
        if not isinstance(address, str):
            _warn_malformed("401 record has no client_ip")
            return
        parsed_address = ipaddress.ip_address(address)
        timestamp = float(record["ts"])
        trusted = _in_trusted_proxy(remote, _trusted_networks())
        if trusted and parsed_address == remote:
            mode = "collapsed"
            packet_drop = False
            _warn_topology(f"trusted proxy {remote} did not provide a distinct client identity")
            return
        elif parsed_address != remote:
            if not trusted:
                _warn_topology(f"untrusted peer {remote} supplied a different client identity {parsed_address}")
                return
            mode = "trusted_proxy"
            packet_drop = False
        elif remote in GATEWAYS:
            mode = "collapsed"
            packet_drop = False
            _warn_topology(f"published ingress collapsed distinct clients at namespace gateway {remote}")
        else:
            mode = "direct"
            packet_drop = True
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
        _warn_malformed(str(error))
        return
    identity = parsed_address.compressed
    _publish_identity(identity, {
        "client_ip": identity,
        "peer_ip": remote.compressed,
        "mode": mode,
        "packet_drop": packet_drop,
        "updated_at": timestamp,
    })
    logger.info(json.dumps({
        "ts": timestamp,
        "status": 401,
        "request": {"remote_ip": remote.compressed, "client_ip": identity, "uri": request.get("uri", "-")},
        "ecd": {"mode": mode, "packet_drop": packet_drop},
    }, separators=(",", ":")))


def follow() -> None:
    offset = 0
    inode = None
    established = False
    missing_since = time.monotonic()
    while True:
        try:
            stat_result = raw_path.stat()
            if not raw_path.is_file():
                raise RuntimeError(f"configured Caddy log is not a regular file: {raw_path}")
            current_inode = stat_result.st_ino
            if current_inode != inode:
                offset = 0
                inode = current_inode
            with raw_path.open(encoding="utf-8", errors="replace") as raw:
                raw.seek(offset)
                for line in raw:
                    process(line)
                offset = raw.tell()
            established = True
            missing_since = time.monotonic()
        except FileNotFoundError as error:
            if established or time.monotonic() - missing_since > 30:
                raise RuntimeError(f"configured Caddy log is unavailable: {raw_path}") from error
        except (OSError, UnicodeError) as error:
            raise RuntimeError(f"cannot follow configured Caddy log {raw_path}: {error}") from error
        time.sleep(0.25)


if __name__ == "__main__":
    try:
        follow()
    except Exception as error:
        print(f"[!] caddy-log-adapter stopped: {error}", file=sys.stderr, flush=True)
        raise SystemExit(1)
