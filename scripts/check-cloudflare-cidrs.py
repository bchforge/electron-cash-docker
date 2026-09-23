#!/usr/bin/env python3
"""Validate the vendored Cloudflare proxy ranges and optionally compare upstream."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from urllib.request import urlopen


ROOT = Path(__file__).resolve().parents[1]
RANGE_FILES = {
    4: ROOT / "docker/caddy/cloudflare-ipv4.txt",
    6: ROOT / "docker/caddy/cloudflare-ipv6.txt",
}
UPSTREAM = {
    4: "https://www.cloudflare.com/ips-v4/",
    6: "https://www.cloudflare.com/ips-v6/",
}


def read_ranges(version: int) -> set[str]:
    path = RANGE_FILES[version]
    if not path.is_file():
        raise ValueError(f"missing Cloudflare range file: {path}")
    values = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not values:
        raise ValueError(f"empty Cloudflare range file: {path}")
    parsed: set[str] = set()
    for value in values:
        try:
            network = ipaddress.ip_network(value, strict=True)
        except ValueError as error:
            raise ValueError(f"invalid Cloudflare {value!r} in {path}") from error
        if network.version != version or network.is_private or network.is_loopback or network.is_link_local:
            raise ValueError(f"unsafe Cloudflare range {value!r} in {path}")
        parsed.add(str(network))
    if len(parsed) != len(values):
        raise ValueError(f"duplicate Cloudflare range in {path}")
    return parsed


def upstream_ranges(version: int) -> set[str]:
    with urlopen(UPSTREAM[version], timeout=15) as response:
        values = response.read().decode("ascii").splitlines()
    return {str(ipaddress.ip_network(value.strip(), strict=True)) for value in values if value.strip()}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-upstream", action="store_true")
    args = parser.parse_args()
    try:
        local = {version: read_ranges(version) for version in RANGE_FILES}
        if args.check_upstream:
            for version in RANGE_FILES:
                upstream = upstream_ranges(version)
                if local[version] != upstream:
                    missing = sorted(upstream - local[version])
                    extra = sorted(local[version] - upstream)
                    raise ValueError(f"Cloudflare IPv{version} ranges differ; missing={missing}, extra={extra}")
        print(f"PASS Cloudflare CIDR validation (IPv4={len(local[4])}, IPv6={len(local[6])}, upstream={args.check_upstream})")
    except (OSError, ValueError) as error:
        print(f"FAIL {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
