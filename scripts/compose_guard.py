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
    expected_caddy_image: str,
    expected_fail2ban_image: str,
    expected_auth_image: str,
    expected_wallet_volume: str,
    expected_tor_volume: str,
    expected_network: str,
    expected_project: str,
) -> None:
    """Reject production names, external resources, and unsafe mounts."""

    serialized = json.dumps(model, sort_keys=True).lower()
    for forbidden in (
        "pro0",
        "production",
        "/var/run/docker.sock",
        "/run/secrets",
    ):
        if forbidden in serialized:
            raise UnsafeComposeModel(f"resolved Compose model contains {forbidden!r}")

    services = model.get("services")
    expected_services = {"electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"}
    if not isinstance(services, dict) or set(services) != expected_services:
        raise UnsafeComposeModel("unexpected Compose services")

    expected_images = {
        "electron-cash": expected_ec_image,
        "tor-proxy": expected_tor_image,
        "caddy": expected_caddy_image,
        "fail2ban": expected_fail2ban_image,
        "auth-session": expected_auth_image,
    }
    expected_mounts = {
        "electron-cash": {"/home/electroncash/.electron-cash": "electron-cash-data"},
        "tor-proxy": {"/var/lib/tor": "tor-data"},
        "caddy": {
            "/data": "caddy-data",
            "/config": "caddy-config",
            "/var/log/caddy": "caddy-log",
            "/var/lib/caddy-bans": "caddy-ban-state",
            "/run/caddy": "caddy-control",
        },
        "fail2ban": {
            "/var/log/caddy": "caddy-log",
            "/var/lib/caddy-bans": "caddy-ban-state",
            "/run/caddy": "caddy-control",
            "/var/lib/fail2ban": "fail2ban-state",
        },
        "auth-session": {},
    }
    for service_name, service in services.items():
        if service.get("image") != expected_images[service_name]:
            raise UnsafeComposeModel(f"{service_name} does not use its CI image")
        if service_name != "fail2ban" and (service.get("container_name") or service.get("network_mode")):
            raise UnsafeComposeModel(f"{service_name} has an explicit container/network name")

        if service_name == "fail2ban":
            if service.get("network_mode") != "service:caddy":
                raise UnsafeComposeModel("fail2ban must share only Caddy's network namespace")
            if service.get("privileged") or service.get("devices") or service.get("ports"):
                raise UnsafeComposeModel("fail2ban has an unsafe privilege or publication setting")
            if set(service.get("cap_add") or []) != {"NET_ADMIN"} or set(service.get("cap_drop") or []) != {"ALL"}:
                raise UnsafeComposeModel("fail2ban capabilities are not least privilege")
            if "networks" in service:
                raise UnsafeComposeModel("fail2ban declares an unexpected network")

        mounts = service.get("volumes", [])
        if not isinstance(mounts, list):
            raise UnsafeComposeModel(f"{service_name} volumes are not a list")
        observed = {}
        bind_mounts = {}
        for mount in mounts:
            if isinstance(mount, dict):
                allowed_types = {"volume", "bind"} if service_name == "caddy" else {"volume"}
                if mount.get("type") not in allowed_types or mount.get("external"):
                    raise UnsafeComposeModel(f"{service_name} has a non-volume or external mount")
                source = _volume_source(mount)
                target = mount.get("target")
            else:
                source = _volume_source(mount)
                target = str(mount).split(":", 2)[1] if ":" in str(mount) else None
            if not source or not target:
                raise UnsafeComposeModel(f"{service_name} has an invalid volume entry")
            if isinstance(mount, dict) and mount.get("type") == "bind":
                bind_mounts[target] = mount
            else:
                observed[target] = source
        if service_name in expected_mounts and observed != expected_mounts[service_name]:
            raise UnsafeComposeModel(f"{service_name} named mounts are not task-owned")

        if service_name == "electron-cash":
            if service.get("ports"):
                raise UnsafeComposeModel("Electron Cash publishes a direct noVNC port")
            if "6080" not in [str(port) for port in service.get("expose", [])]:
                raise UnsafeComposeModel("Electron Cash noVNC endpoint is not internal-only")
        elif service_name == "caddy":
            if service.get("privileged") or service.get("devices"):
                raise UnsafeComposeModel("Caddy has an unsafe privilege or device setting")
            ports = service.get("ports") or []
            if {port.get("target") for port in ports if isinstance(port, dict)} != {80, 443} or len(ports) != 2:
                raise UnsafeComposeModel("Caddy must publish only HTTP and HTTPS edge ports")
            for port in ports:
                if not isinstance(port, dict) or port.get("protocol") != "tcp":
                    raise UnsafeComposeModel("Caddy edge port is not TCP")
                if port.get("host_ip") not in {"127.0.0.1", "::1"}:
                    raise UnsafeComposeModel("Caddy bind is not loopback-only in CI")
            if set(bind_mounts) != {"/etc/caddy/entrypoint.sh"}:
                raise UnsafeComposeModel("Caddy has unexpected host bind targets")
            caddy_environment = service.get("environment")
            if not isinstance(caddy_environment, dict) or caddy_environment.get("AUTH_SESSION_UPSTREAM") != "auth-session:8080":
                raise UnsafeComposeModel("Caddy does not use the private auth-session upstream")
            entrypoint_mount = bind_mounts["/etc/caddy/entrypoint.sh"]
            if (
                not str(entrypoint_mount.get("source", "")).endswith("/docker/caddy-entrypoint.sh")
                or not entrypoint_mount.get("read_only")
                or entrypoint_mount.get("bind", {}).get("create_host_path") is not False
            ):
                raise UnsafeComposeModel("Caddy entrypoint bind is not the task-owned read-only file")
        elif service_name == "fail2ban":
            log_mount = next(
                (mount for mount in mounts if isinstance(mount, dict) and mount.get("target") == "/var/log/caddy"),
                None,
            )
            if not log_mount or not log_mount.get("read_only"):
                raise UnsafeComposeModel("Fail2ban Caddy log mount is not read-only")

        if service_name != "fail2ban":
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

        if service_name == "auth-session":
            if service.get("ports") or service.get("privileged") or service.get("devices"):
                raise UnsafeComposeModel("auth-session has an unsafe publication or privilege setting")
            if service.get("cap_add") or set(service.get("cap_drop") or []) != {"ALL"}:
                raise UnsafeComposeModel("auth-session capabilities are not least privilege")
            environment = service.get("environment")
            if not isinstance(environment, dict) or "BASIC_AUTH_PASSWORD" not in environment:
                raise UnsafeComposeModel("auth-session does not receive an explicit password")

    volumes = model.get("volumes", {})
    required_volumes = {
        "electron-cash-data",
        "tor-data",
        "caddy-data",
        "caddy-config",
        "caddy-log",
        "fail2ban-state",
        "caddy-ban-state",
        "caddy-control",
    }
    if set(volumes) != required_volumes:
        raise UnsafeComposeModel("unexpected Compose volumes")
    if volumes["electron-cash-data"].get("name") != expected_wallet_volume:
        raise UnsafeComposeModel("wallet volume is not task-owned")
    if volumes["tor-data"].get("name") != expected_tor_volume:
        raise UnsafeComposeModel("Tor volume is not task-owned")
    for name in required_volumes - {"electron-cash-data", "tor-data"}:
        volume_name = volumes[name].get("name")
        if not volume_name or not volume_name.startswith(f"{expected_project}_"):
            raise UnsafeComposeModel(f"Compose volume {name} is not task-owned")
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
