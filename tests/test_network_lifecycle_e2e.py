#!/usr/bin/env python3
"""Fresh single-volume, all-network daemon lifecycle through actual Compose."""
import json
import os
import subprocess
import time
from pathlib import Path

from test_support import (electron_cash_image, remove_owned_volume, tor_image,
                          unique_project, unique_resource)

ROOT = Path(__file__).resolve().parents[1]
NETWORKS = {"mainnet": "", "chipnet": "--chipnet", "testnet": "--testnet",
            "testnet4": "--testnet4", "scalenet": "--scalenet", "regtest": "--regtest"}
BASE = "/home/electroncash/.electron-cash"


def checked(command, *, env, timeout=150):
    result = subprocess.run(command, cwd=ROOT, env=env, text=True, capture_output=True, timeout=timeout)
    assert result.returncode == 0, (command, result.stdout, result.stderr)
    return result.stdout


def main():
    project = unique_project("network-lifecycle")
    wallet = unique_resource("network-lifecycle-wallet")
    tor = unique_resource("network-lifecycle-tor")
    command = ["docker", "compose", "--env-file", str(ROOT / ".env.example"), "-p", project,
               "-f", "docker-compose.yml", "-f", "docker-compose.headless.yml"]
    env = {**os.environ, "ELECTRON_CASH_IMAGE": electron_cash_image(), "TOR_IMAGE": tor_image(),
           "ECD_WALLET_VOLUME": wallet, "ECD_TOR_VOLUME": tor,
           "BASIC_AUTH_PASSWORD": "synthetic-e2e", "USE_TOR": "true",
           "WALLET_AUTO_CREATE": "false", "TEST_WALLET_PASSWORD": "",
           "CHIPNET": "false", "TESTNET4": "false"}
    snapshots = {}
    try:
        for network, flag in NETWORKS.items():
            env["NETWORK"] = network
            checked([*command, "up", "-d", "--no-build"], env=env)
            container = checked([*command, "ps", "-q", "electron-cash"], env=env).strip()
            assert container
            deadline = time.monotonic() + 90
            # Before startup completes, even the status CLI initializes and
            # writes SimpleConfig. Do not race the entrypoint's initial policy.
            while "[+] Electron Cash daemon ready" not in checked(
                    ["docker", "logs", container], env=env):
                assert time.monotonic() < deadline, (network, "daemon startup did not complete")
                time.sleep(1)
            while True:
                result = subprocess.run(["docker", "exec", "--user", "10001:10001", container,
                                         "/opt/electroncash-venv/bin/electron-cash",
                                         *([flag] if flag else []), "daemon", "status"],
                                        cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    break
                assert time.monotonic() < deadline, result.stderr
                time.sleep(2)
            path = BASE if network == "mainnet" else f"{BASE}/{network}"
            config_deadline = time.monotonic() + 30
            config = None
            last_config_keys = []
            while time.monotonic() < config_deadline:
                config_result = subprocess.run(
                    ["docker", "exec", "--user", "10001:10001", container,
                     "/opt/electroncash-venv/bin/python", "-c",
                     "import json,sys;print(json.dumps(json.load(open(sys.argv[1]))))", path + "/config"],
                    cwd=ROOT, env=env, capture_output=True, text=True, timeout=10)
                if config_result.returncode == 0:
                    try:
                        candidate_config = json.loads(config_result.stdout)
                    except json.JSONDecodeError:
                        candidate_config = None
                    if isinstance(candidate_config, dict):
                        last_config_keys = sorted(candidate_config)
                    if isinstance(candidate_config, dict) and candidate_config.get("proxy") == "socks5:tor-proxy:9050":
                        config = candidate_config
                        break
                time.sleep(1)
            assert config is not None, (network, "Tor proxy configuration not initialized", last_config_keys)
            # Probe the real local RPC service repeatedly without allowing a
            # health/readiness check to rewrite preferences or credentials.
            digest_command = ['docker', 'exec', '--user', '10001:10001', container,
                '/opt/electroncash-venv/bin/python', '-c',
                'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())', path+'/config']
            before_health = checked(digest_command, env=env)
            checked(['docker', 'exec', '--user', '10001:10001', container,
                '/opt/electroncash-venv/bin/python', '-c',
                'import healthcheck; [healthcheck.main() for _ in range(20)]'], env=env)
            assert checked(digest_command, env=env) == before_health, (network, 'health changed configuration')
            checked(["docker", "exec", "--user", "10001:10001", container,
                     "/opt/electroncash-venv/bin/python", "-c",
                     "import sys;open(sys.argv[1], 'w').write(sys.argv[2])",
                      path + "/.ecd-network-lifecycle-marker", network], env=env)
            inspection = json.loads(checked(["docker", "inspect", container], env=env))[0]
            wallet_mounts = [mount for mount in inspection["Mounts"]
                             if mount["Destination"] == BASE]
            assert len(wallet_mounts) == 1
            assert wallet_mounts[0]["Name"] == wallet and wallet_mounts[0]["RW"] is True
            assert not inspection["HostConfig"]["PortBindings"]
            assert not inspection["HostConfig"]["Privileged"]
            assert inspection["Config"]["Env"].count(f"NETWORK={network}") == 1
            assert {"auth-session", "caddy", "fail2ban"}.isdisjoint(
                json.loads(checked([*command, "config", "--format", "json"], env=env))["services"])
            snapshots[network] = path
            print(f"PASS {network} daemon in {path} with Tor and no host port", flush=True)
        for network, path in snapshots.items():
            value = checked(["docker", "run", "--pull=never", "--rm", "--network", "none",
                             "--mount", f"type=volume,src={wallet},dst=/wallet,readonly",
                             "--entrypoint", "python3", electron_cash_image(), "-c",
                             "import pathlib,sys;print(pathlib.Path(sys.argv[1]).read_text())",
                              "/wallet" + path.removeprefix(BASE) + "/.ecd-network-lifecycle-marker"], env=env).strip()
            assert value == network
        checked([*command, "restart", "electron-cash"], env=env)
        print("PASS six isolated network markers survive recreation and restart", flush=True)
    finally:
        checked([*command, "down", "--remove-orphans"], env=env)
        remove_owned_volume(wallet)
        remove_owned_volume(tor)


if __name__ == "__main__":
    main()
