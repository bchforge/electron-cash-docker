#!/usr/bin/env python3
"""Compose selects capabilities, never a BCH network."""
import json
import os
import subprocess
import tempfile
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "docker"))
from network_selection import NetworkSelectionError, network_from_compose

ROOT = Path(__file__).resolve().parents[1]


def resolved(overlays=(), network="mainnet", extra=(), last=()):
    env = {**os.environ, "BASIC_AUTH_PASSWORD": "synthetic-secret", "NETWORK": network,
           "DISPLAY": ":0", "XAUTHORITY": "/tmp/synthetic-xauthority",
           "HW_USB_GID": str(os.getgid() or os.getuid() or 10001),
           "JSONRPC_HOST_PORT": "15002", "CADDY_HTTP_HOST_PORT": "18081",
           "CADDY_HTTPS_HOST_PORT": "18443"}
    env.pop("ECD_HW_IMAGE", None)
    env.pop("COMPOSE_PROFILES", None)
    command = ["docker", "compose", "--env-file", str(ROOT / ".env.example"),
               "-f", str(ROOT / "docker-compose.yml")]
    for overlay in (*extra, *overlays, *last):
        command += ["-f", str(overlay if isinstance(overlay, Path) else ROOT / f"docker-compose.{overlay}.yml")]
    result = subprocess.run([*command, "config", "--format", "json"], cwd=ROOT,
                            env=env, text=True, capture_output=True, timeout=60)
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


def main():
    assert not (ROOT / "docker-compose.chipnet.yml").exists()
    assert not (ROOT / "docker-compose.testnet4.yml").exists()
    base = resolved()
    assert set(base["services"]) == {"electron-cash", "tor-proxy", "auth-session", "caddy", "fail2ban"}
    assert base["services"]["electron-cash"]["environment"]["NETWORK"] == "mainnet"
    assert all(service.get("build") and service.get("pull_policy") == "never"
               for service in base["services"].values())
    assert base["services"]["caddy"]["build"]["entitlements"] == ["network.host"]
    caddy_dockerfile = (ROOT / "docker/caddy/Dockerfile").read_text(encoding="utf-8")
    assert "sha256sum go.mod go.sum > /out/upstream-module-locks.sha256" in caddy_dockerfile
    assert "go mod download && go mod verify" in caddy_dockerfile
    assert "go mod edit -require=golang.org/x/net@v0.60.0" in caddy_dockerfile
    for network in ("chipnet", "testnet", "testnet4", "scalenet", "regtest"):
        model = resolved(network=network)
        assert set(model["services"]) == set(base["services"])
        assert model["services"]["electron-cash"]["environment"]["NETWORK"] == network
    empty = resolved(network="")
    assert empty["services"]["electron-cash"]["environment"]["NETWORK"] == ""
    try:
        network_from_compose(empty)
    except NetworkSelectionError as error:
        assert "invalid NETWORK" in str(error)
    else:
        raise AssertionError("explicitly empty NETWORK fell back to mainnet")
    for overlay in ("headless", "gui"):
        model = resolved((overlay,), "chipnet")
        expected = {"electron-cash", "tor-proxy"}
        if overlay == "gui":
            expected.add("x11-authority")
        assert set(model["services"]) == expected, model["services"]
        wallet = model["services"]["electron-cash"]
        assert not wallet.get("ports") and wallet["environment"]["MODE"] == overlay
        assert wallet["environment"]["NETWORK"] == "chipnet"
        assert wallet["volumes"][0] == base["services"]["electron-cash"]["volumes"][0]
    gui = resolved(("gui",))["services"]["electron-cash"]
    assert gui["environment"]["DISPLAY"] == ":0"
    assert gui["environment"]["XAUTHORITY"] == "/run/ecd-x11/authority"
    assert all(volume["read_only"] for volume in gui["volumes"][1:])
    x11_helper = resolved(("gui",))["services"]["x11-authority"]
    assert x11_helper["pull_policy"] == "never" and x11_helper["network_mode"] == "none"
    assert x11_helper["cap_drop"] == ["ALL"]
    assert set(x11_helper["cap_add"]) == {"CHOWN", "DAC_READ_SEARCH"}
    assert x11_helper["user"] == "0:0" and not x11_helper.get("privileged")
    assert all(volume["read_only"] for volume in x11_helper["volumes"][:2])
    assert x11_helper["volumes"][0]["bind"]["create_host_path"] is False
    with tempfile.TemporaryDirectory() as temp:
        mac = Path(temp) / "mac-xquartz.yml"
        mac.write_text(
            '{"services":{"electron-cash":{"environment":{"XAUTHORITY":"/home/electroncash/.Xauthority"},'
            '"volumes": !override ['
            '{"type":"volume","source":"electron-cash-data","target":"/home/electroncash/.electron-cash"},'
            '{"type":"bind","source":"/tmp/xauth","target":"/home/electroncash/.Xauthority",'
            '"read_only":true,"bind":{"create_host_path":false}}]}}}\n'
        )
        mac_gui = resolved(("gui",), last=(mac,))["services"]["electron-cash"]
        assert len(mac_gui["volumes"]) == 2
        assert mac_gui["environment"]["XAUTHORITY"] == "/home/electroncash/.Xauthority"
        assert all(volume["target"] != "/tmp/.X11-unix" for volume in mac_gui["volumes"])
    rpc = resolved(("headless", "rpc"))["services"]["electron-cash"]
    assert len(rpc["ports"]) == 1 and rpc["ports"][0]["host_ip"] == "127.0.0.1"
    assert rpc["environment"]["ECD_HEADLESS_OVERLAY"] == "true"
    assert rpc["environment"]["ECD_RPC_OVERLAY"] == "true"
    gui_rpc = resolved(("gui", "rpc"))["services"]["electron-cash"]
    assert gui_rpc["environment"]["ECD_GUI_OVERLAY"] == "true"
    assert "JSON-RPC requires the headless and RPC overlays" in (ROOT / "docker/entrypoint.sh").read_text()
    hw_services = resolved(("gui", "hw"))["services"]
    hw = hw_services["electron-cash"]
    assert hw["build"]["args"]["HW_SUPPORT"] == "1"
    assert hw["pull_policy"] == "never"
    assert hw["image"] == "electron-cash:4.4.6-hw"
    assert hw["image"] != base["services"]["electron-cash"]["image"]
    assert hw["environment"]["HW_USB_GID"] == str(os.getgid() or os.getuid() or 10001)
    assert hw_services["x11-authority"]["image"] == hw["image"]
    assert hw_services["x11-authority"]["pull_policy"] == "never"
    assert hw["devices"] and hw["device_cgroup_rules"] == ["c 189:* rw"]
    assert not hw.get("privileged") and not base["services"]["electron-cash"].get("devices")
    with tempfile.TemporaryDirectory() as temp:
        previous = Path(temp) / "earlier.yml"
        previous.write_text('services:\n  electron-cash:\n    ports: ["127.0.0.1:16080:6080"]\n')
        for overlay in ("headless", "gui"):
            assert not resolved((overlay,), extra=(previous,))["services"]["electron-cash"].get("ports")
    print("PASS generic network and capability Compose matrix, port resets and Ledger isolation")


if __name__ == "__main__":
    main()
