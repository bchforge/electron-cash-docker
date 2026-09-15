"""Safety checks for resolved Compose models used by CI acceptance."""

from __future__ import annotations

import json
from typing import Any


class UnsafeComposeModel(ValueError):
    """Raised when a resolved Compose model can address non-CI resources."""


def _volume_source(volume: Any) -> str | None:
    if isinstance(volume, str):
        return volume.split(":", 1)[0]
    if isinstance(volume, dict):
        return volume.get("source") or volume.get("name")
    return None


def _network_name(network: Any) -> str | None:
    if isinstance(network, str):
        return network
    if isinstance(network, dict):
        return network.get("name")
    return None


def validate_resolved_model(
    model: dict[str, Any],
    *,
    expected_ec_image: str,
    expected_tor_image: str,
    expected_wallet_volume: str,
    expected_tor_volume: str,
    expected_network: str,
    expected_project: str,
) -> None:
    """Reject production names, external resources, and unsafe mounts."""

    serialized = json.dumps(model, sort_keys=True).lower()
    for forbidden in ("pro0", "production", "/var/run/docker.sock"):
        if forbidden in serialized:
            raise UnsafeComposeModel(f"resolved Compose model contains {forbidden!r}")

    services = model.get("services")
    if not isinstance(services, dict) or set(services) != {"electron-cash", "tor-proxy"}:
        raise UnsafeComposeModel("unexpected Compose services")

    expected_images = {
        "electron-cash": expected_ec_image,
        "tor-proxy": expected_tor_image,
    }
    expected_mounts = {
        "electron-cash": {"/home/electroncash/.electron-cash": "electron-cash-data"},
        "tor-proxy": {"/var/lib/tor": "tor-data"},
    }
    for service_name, service in services.items():
        if service.get("image") != expected_images[service_name]:
            raise UnsafeComposeModel(f"{service_name} does not use its CI image")
        if service.get("container_name") or service.get("network_mode"):
            raise UnsafeComposeModel(f"{service_name} has an explicit container/network name")

        mounts = service.get("volumes", [])
        if not isinstance(mounts, list):
            raise UnsafeComposeModel(f"{service_name} volumes are not a list")
        observed = {}
        for mount in mounts:
            if isinstance(mount, dict):
                if mount.get("type") != "volume" or mount.get("external"):
                    raise UnsafeComposeModel(f"{service_name} has a non-volume or external mount")
                source = _volume_source(mount)
                target = mount.get("target")
            else:
                source = _volume_source(mount)
                target = str(mount).split(":", 2)[1] if ":" in str(mount) else None
            if not source or not target:
                raise UnsafeComposeModel(f"{service_name} has an invalid volume entry")
            observed[target] = source
        if observed != expected_mounts[service_name]:
            raise UnsafeComposeModel(f"{service_name} mounts are not task-owned")

        networks = service.get("networks", [])
        if isinstance(networks, dict):
            network_names = {_network_name(value) or key for key, value in networks.items()}
        else:
            network_names = {_network_name(value) for value in networks}
        if network_names != {"electron-network"}:
            raise UnsafeComposeModel(f"{service_name} network is not task-owned")

        if service.get("ports"):
            for port in service["ports"]:
                if isinstance(port, dict):
                    host_ip = port.get("host_ip", "")
                    if host_ip not in {"127.0.0.1", "::1"}:
                        raise UnsafeComposeModel("published port is not loopback-only")
                elif "127.0.0.1" not in str(port) and "::1" not in str(port):
                    raise UnsafeComposeModel("published port is not loopback-only")

    volumes = model.get("volumes", {})
    if set(volumes) != {"electron-cash-data", "tor-data"}:
        raise UnsafeComposeModel("unexpected Compose volumes")
    names = {volumes[key].get("name") for key in volumes if isinstance(volumes[key], dict)}
    if names != {expected_wallet_volume, expected_tor_volume}:
        raise UnsafeComposeModel("Compose volume names are not task-owned")
    if any(isinstance(value, dict) and value.get("external") for value in volumes.values()):
        raise UnsafeComposeModel("external Compose volume")

    networks = model.get("networks", {})
    if set(networks) != {"electron-network"}:
        raise UnsafeComposeModel("unexpected Compose networks")
    network = networks["electron-network"]
    if not isinstance(network, dict) or network.get("name") != expected_network or network.get("external"):
        raise UnsafeComposeModel("network is not task-owned")

    project = model.get("name")
    if project and project != expected_project:
        raise UnsafeComposeModel("resolved Compose project name changed")
