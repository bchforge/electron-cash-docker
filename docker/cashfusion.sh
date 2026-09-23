#!/bin/bash

set -euo pipefail

CONFIG_FILE="${CONFIG_FILE:-/home/electroncash/.electron-cash/config}"
CONFIG_DIR="$(dirname "${CONFIG_FILE}")"
CASHFUSION_ENABLED="${CASHFUSION_ENABLED:-true}"
CASHFUSION_ENABLED="${CASHFUSION_ENABLED,,}"

mkdir -p "${CONFIG_DIR}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${CONFIG_FILE}" PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}" python3 - <<'PY'
import json
import os
import tempfile

from cashfusion_defaults import (
    CashFusionConfigurationError,
    cashfusion_config_from_environment,
)

config_path = os.environ["CONFIG_FILE"]
config_dir = os.path.dirname(config_path) or "."

try:
    enabled = cashfusion_config_from_environment()["enabled"]
except CashFusionConfigurationError as error:
    print(f"[!] {error}")
    raise SystemExit(1)

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
    echo "[+] CashFusion enabled (missing wallet defaults apply when eligible wallets open)"
else
    echo "[*] CashFusion disabled"
fi
