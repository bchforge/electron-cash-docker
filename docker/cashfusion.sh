#!/bin/bash

set -euo pipefail

CASHFUSION_ENABLED=${CASHFUSION_ENABLED:-false}
CASHFUSION_AUTO_FUSE=${CASHFUSION_AUTO_FUSE:-false}

case "${CASHFUSION_ENABLED}" in
    true|false) ;;
    *) echo "[!] CASHFUSION_ENABLED must be true or false"; exit 1 ;;
esac
case "${CASHFUSION_AUTO_FUSE}" in
    true|false) ;;
    *) echo "[!] CASHFUSION_AUTO_FUSE must be true or false"; exit 1 ;;
esac

CONFIG_FILE="${CONFIG_FILE:-/home/electroncash/.electron-cash/config}"
CONFIG_DIR="$(dirname "${CONFIG_FILE}")"

mkdir -p "${CONFIG_DIR}"

CONFIG_FILE="${CONFIG_FILE}" CASHFUSION_ENABLED="${CASHFUSION_ENABLED}" python3 - <<'PY'
import json
import os
import tempfile

config_path = os.environ["CONFIG_FILE"]
config_dir = os.path.dirname(config_path) or "."
enabled = os.environ["CASHFUSION_ENABLED"] == "true"

try:
    with open(config_path) as handle:
        config = json.load(handle)
except FileNotFoundError:
    config = {}

config["use_fusion"] = enabled
config["cashfusion_tor_host"] = "tor-proxy"
config["cashfusion_tor_port_auto"] = False
config["cashfusion_tor_port_manual"] = 9050

fd, temporary_path = tempfile.mkstemp(
    prefix=".config.", dir=config_dir
)
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=4, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, config_path)
finally:
    if os.path.exists(temporary_path):
        os.unlink(temporary_path)

print(f"[+] Global: use_fusion = {enabled}")
PY

chmod 600 "${CONFIG_FILE}"

if [ "${CASHFUSION_ENABLED}" = "true" ]; then
    if [ "${CASHFUSION_AUTO_FUSE}" = "true" ]; then
        echo "[+] CashFusion enabled (auto-fuse applies when a wallet opens)"
    else
        echo "[+] CashFusion enabled (auto-fuse disabled)"
    fi
else
    if [ "${CASHFUSION_AUTO_FUSE}" = "true" ]; then
        echo "[*] CashFusion autofuse ignored (plugin disabled)"
    fi
    echo "[*] CashFusion disabled"
fi
