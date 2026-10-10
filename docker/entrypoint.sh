#!/bin/bash

set -euo pipefail

export HOME=/home/electroncash
export XDG_RUNTIME_DIR=/tmp/runtime-electroncash

MODE=${MODE:-novnc}
EC_LANGUAGE=${EC_LANGUAGE-en_US}
if ! EC_LANGUAGE="${EC_LANGUAGE}" /opt/electroncash-venv/bin/python - <<'PY'
import os
from electroncash.i18n import languages
if os.environ['EC_LANGUAGE'] not in languages:
    raise SystemExit('[!] EC_LANGUAGE must be an official Electron Cash locale or empty (System)')
PY
then
    exit 1
fi
ECD_VERSION_FILE=/etc/electroncash-docker/VERSION
if [[ ! -r "${ECD_VERSION_FILE}" ]]; then
    echo "[!] missing product version file: ${ECD_VERSION_FILE}"
    exit 1
fi
ECD_PRODUCT_VERSION=$(tr -d '\r\n' < "${ECD_VERSION_FILE}")
if [[ ! "${ECD_PRODUCT_VERSION}" =~ ^[0-9]+\.[0-9]+$ ]]; then
    echo "[!] invalid product version: ${ECD_PRODUCT_VERSION}"
    exit 1
fi
USE_TOR=${USE_TOR:?USE_TOR must be set}
CASHFUSION_ENABLED=${CASHFUSION_ENABLED:-true}
WALLET_AUTO_CREATE=${WALLET_AUTO_CREATE:-false}
TEST_WALLET_PASSWORD=${TEST_WALLET_PASSWORD:-}
ELECTRONCASH_RUNTIME=${ELECTRONCASH_RUNTIME:-false}
JSONRPC_ENABLED=${JSONRPC_ENABLED:-false}
JSONRPC_USER=${JSONRPC_USER:-}
JSONRPC_PASSWORD=${JSONRPC_PASSWORD:-}
JSONRPC_PORT=${JSONRPC_PORT:-50001}

if ! NETWORK_DETAILS=$(/opt/electroncash-venv/bin/python /home/electroncash/network_selection.py --details); then
    exit 1
fi
read -r NETWORK_LABEL NETWORK_FLAG CONFIG_DIR <<< "${NETWORK_DETAILS}"
EC_NET_FLAG=()
if [ "${NETWORK_FLAG}" != - ]; then EC_NET_FLAG=("${NETWORK_FLAG}"); fi
mapfile -d '' -t EC_EXTRA_ARGS < <(/opt/electroncash-venv/bin/python /home/electroncash/network_selection.py --args)

case "${MODE}" in
    novnc|headless|gui) ;;
    *) echo "[!] MODE must be novnc, headless or gui"; exit 1 ;;
esac
if [ "${ECD_HEADLESS_OVERLAY:-false}" = true ] && [ "${ECD_GUI_OVERLAY:-false}" = true ]; then
    echo "[!] headless and native GUI overlays cannot be combined"; exit 1
fi
if [ "${JSONRPC_ENABLED:-false}" = true ]; then
    if [ "${ECD_RPC_OVERLAY:-false}" != true ] || [ "${ECD_HEADLESS_OVERLAY:-false}" != true ] || \
        [ "${ECD_GUI_OVERLAY:-false}" = true ]; then
        echo "[!] JSON-RPC requires the headless and RPC overlays and cannot be combined with native GUI"; exit 1
    fi
fi
if [ "${HW_SUPPORT:-0}" = 1 ] && [ "${ECD_GUI_OVERLAY:-false}" != true ]; then
    echo "[!] Ledger requires the native GUI overlay on Linux"; exit 1
fi
if [ "${MODE}" = gui ]; then
    if [ -z "${DISPLAY:-}" ] || [ "${DISPLAY}" = :99 ]; then
        echo "[!] native GUI requires a host DISPLAY (not :99)"; exit 1
    fi
    if ! xdpyinfo -display "${DISPLAY}" >/dev/null 2>&1; then
        echo "[!] host X11 display is unavailable: ${DISPLAY}"; exit 1
    fi
else
    export DISPLAY=:99
fi

case "${USE_TOR}" in
    true|false) ;;
    *) echo "[!] USE_TOR must be true or false"; exit 1 ;;
esac
CASHFUSION_ENABLED="${CASHFUSION_ENABLED,,}"
case "${CASHFUSION_ENABLED}" in
    true|false) ;;
    *) echo "[!] CASHFUSION_ENABLED must be true or false"; exit 1 ;;
esac
case "${WALLET_AUTO_CREATE}" in
    true|false) ;;
    *) echo "[!] WALLET_AUTO_CREATE must be true or false"; exit 1 ;;
esac
case "${TEST_WALLET_PASSWORD}" in
    *[!A-Za-z0-9._-]*)
        echo "[!] TEST_WALLET_PASSWORD may contain only letters, numbers, dot, underscore, and hyphen"
        exit 1
        ;;
esac

case "${JSONRPC_ENABLED}" in
    true|false) ;;
    *) echo "[!] JSONRPC_ENABLED must be true or false"; exit 1 ;;
esac
if [ "${JSONRPC_ENABLED}" = "true" ]; then
    if [ "${MODE}" != "headless" ]; then
        echo "[!] JSON-RPC is supported only in headless mode"
        exit 1
    fi
    if [ -z "${JSONRPC_PASSWORD}" ]; then
        echo "[!] JSONRPC_ENABLED=true requires a non-empty JSONRPC_PASSWORD"
        exit 1
    fi
    if [ -z "${JSONRPC_USER}" ]; then
        echo "[!] JSONRPC_ENABLED=true requires a non-empty JSONRPC_USER"
        exit 1
    fi
    case "${JSONRPC_USER}" in
        *[!A-Za-z0-9._-]*) echo "[!] JSONRPC_USER contains unsupported characters"; exit 1 ;;
    esac
    case "${JSONRPC_PASSWORD}" in
        *$'\n'*|*$'\r'*) echo "[!] JSONRPC_PASSWORD must not contain newlines"; exit 1 ;;
    esac
fi
case "${JSONRPC_PORT}" in
    ''|*[!0-9]*) echo "[!] JSONRPC_PORT must be numeric"; exit 1 ;;
esac
if [ "${JSONRPC_PORT}" -lt 1 ] || [ "${JSONRPC_PORT}" -gt 65535 ]; then
    echo "[!] JSONRPC_PORT must be between 1 and 65535"
    exit 1
fi

if ! PYTHONPATH=/home/electroncash python3 - <<'PY'
from cashfusion_defaults import (
    CashFusionConfigurationError,
    cashfusion_config_from_environment,
)
from gui_startup import theme_from_environment

try:
    cashfusion_config_from_environment()
    theme_from_environment()
except (CashFusionConfigurationError, ValueError) as error:
    print(f"[!] {error}")
    raise SystemExit(1)
PY
then
    exit 1
fi

readonly WALLET_ROOT=/home/electroncash/.electron-cash
readonly WALLET_MARKER=${WALLET_ROOT}/.electron-cash-docker
readonly EXPECTED_MARKER=electron-cash-docker-v0.1
CONFIG_FILE="${CONFIG_DIR}/config"
WALLET_FILE="${CONFIG_DIR}/wallets/default_wallet"

if [ "${NETWORK_LABEL}" != "chipnet" ] && {
    [ "${WALLET_AUTO_CREATE}" = "true" ] || [ -n "${TEST_WALLET_PASSWORD}" ];
}; then
    echo "[!] WALLET_AUTO_CREATE and TEST_WALLET_PASSWORD require NETWORK=chipnet"
    exit 1
fi

access_probe() {
    setpriv --reuid 10001 --regid 10001 --clear-groups -- \
        env HOME=/home/electroncash python3 - "${WALLET_ROOT}" <<'PY'
import os
import sys
import tempfile
from pathlib import Path

APP_UID = 10001
APP_GID = 10001
root = Path(sys.argv[1])
first = None
second = None

try:
    if os.getuid() != APP_UID or os.getgid() != APP_GID or os.getgroups():
        raise RuntimeError("effective application identity is incorrect")

    fd, first_name = tempfile.mkstemp(
        prefix=".electron-cash-docker.probe-", dir=root
    )
    first = Path(first_name)
    with os.fdopen(fd, "wb") as handle:
        handle.write(b"electron-cash-docker-access-probe")
        handle.flush()
        os.fsync(handle.fileno())

    if first.read_bytes() != b"electron-cash-docker-access-probe":
        raise RuntimeError("access probe read failed")

    second = first.with_name(first.name + ".renamed")
    os.replace(first, second)
    first = None
    if second.read_bytes() != b"electron-cash-docker-access-probe":
        raise RuntimeError("access probe rename/read failed")
    second.unlink()
    second = None
except Exception as error:
    raise SystemExit(f"access probe failed: {error}")
finally:
    for path in (first, second):
        if path is not None:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
PY
}

initialize_wallet_root() {
    if ! mountpoint -q "${WALLET_ROOT}"; then
        echo "[!] wallet data path is not a mounted Docker volume"
        return 1
    fi
    if [ -L "${WALLET_ROOT}" ] || [ ! -d "${WALLET_ROOT}" ]; then
        echo "[!] wallet data path must be a directory and must not be a symbolic link"
        return 1
    fi

    local symlink_entry
    symlink_entry=$(find -P "${WALLET_ROOT}" -xdev -type l -print -quit) || {
        echo "[!] unable to inspect wallet volume"
        return 1
    }
    if [ -n "${symlink_entry}" ]; then
        echo "[!] wallet data must not contain symbolic links: ${symlink_entry}"
        return 1
    fi

    local marker_present=false
    if [ -e "${WALLET_MARKER}" ] || [ -L "${WALLET_MARKER}" ]; then
        marker_present=true
    fi

    if [ "${marker_present}" = true ]; then
        if [ -L "${WALLET_MARKER}" ] || [ ! -f "${WALLET_MARKER}" ] || \
            ! printf '%s\n' "${EXPECTED_MARKER}" | cmp -s - "${WALLET_MARKER}"; then
            echo "[!] invalid wallet data marker"
            return 1
        fi
    else
        local existing_entry
        existing_entry=$(find -P "${WALLET_ROOT}" -xdev \
            -mindepth 1 -maxdepth 1 -print -quit) || {
            echo "[!] unable to inspect wallet volume"
            return 1
        }
        if [ -n "${existing_entry}" ]; then
            echo "[!] wallet volume must be empty on first use or have the expected marker"
            return 1
        fi

        chmod 700 "${WALLET_ROOT}"
        printf '%s\n' "${EXPECTED_MARKER}" > "${WALLET_MARKER}"
        chmod 600 "${WALLET_MARKER}"
        chown 10001:10001 "${WALLET_ROOT}" "${WALLET_MARKER}"
    fi

    if [ "$(stat -c '%u:%g' "${WALLET_ROOT}")" != "10001:10001" ] || \
        [ "$(stat -c '%a' "${WALLET_ROOT}")" != "700" ]; then
        echo "[!] wallet volume root ownership or mode is invalid"
        return 1
    fi
    if [ "$(stat -c '%u:%g' "${WALLET_MARKER}")" != "10001:10001" ] || \
        [ "$(stat -c '%a' "${WALLET_MARKER}")" != "600" ]; then
        echo "[!] wallet marker ownership or mode is invalid"
        return 1
    fi

    local incompatible_entry
    incompatible_entry=$(find -P "${WALLET_ROOT}" -xdev -mindepth 1 \
        \( ! -uid 10001 -o ! -gid 10001 \) -print -quit) || {
        echo "[!] unable to validate wallet data ownership"
        return 1
    }
    if [ -n "${incompatible_entry}" ]; then
        echo "[!] wallet data ownership does not match 10001:10001: ${incompatible_entry}"
        return 1
    fi

    access_probe
    echo "[+] Wallet volume initialized and access-checked"
}

if [ "$(id -u)" -eq 0 ] && [ "${ELECTRONCASH_RUNTIME}" != "true" ]; then
    initialize_wallet_root
    runtime_groups=(--clear-groups)
    if [ "${HW_SUPPORT:-0}" = 1 ]; then
        [ -d /dev/bus/usb ] || { echo "[!] Ledger USB devices are unavailable"; exit 1; }
        case "${HW_USB_GID:-}" in
            ''|*[!0-9]*) echo "[!] HW_USB_GID must be the numeric group of the Ledger USB node"; exit 1 ;;
        esac
        runtime_groups=(--groups "${HW_USB_GID:?HW_USB_GID must identify the Linux USB device group}")
    fi
    exec setpriv --reuid 10001 --regid 10001 "${runtime_groups[@]}" -- \
        env ELECTRONCASH_RUNTIME=true HOME=/home/electroncash \
        XDG_RUNTIME_DIR=/tmp/runtime-electroncash "$0" "$@"
fi

if [ "$(id -u)" -ne 10001 ] || [ "$(id -g)" -ne 10001 ]; then
    echo "[!] Electron Cash runtime must use UID/GID 10001:10001"
    exit 1
fi

# Keep the credential out of child process environments unless explicitly
# passed to the short-lived config writer below.
export -n JSONRPC_PASSWORD 2>/dev/null || true

XVFB_PID=""
OPENBOX_PID=""
X11VNC_PID=""
WEBSOCKIFY_PID=""
ELECTRONCASH_PID=""
SHUTDOWN_MARKER=/tmp/electron-cash-shutdown

kill_gracefully() {
    local pid=$1
    local name=$2
    if [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null; then
        echo "[*] Stopping ${name}"
        if [ "${name}" = x11vnc ] && timeout 2 x11vnc -display :99 -R stop >/dev/null 2>&1; then
            # Ask the owned server to exit in its normal X11 event loop.
            # SIGTERM can interrupt Xlib cleanup while a client is closing.
            :
        elif [ "${name}" = openbox ] && DISPLAY=:99 timeout 2 openbox --exit >/dev/null 2>&1; then
            :  # same owned-display event-loop shutdown for the window manager
        else
            kill -TERM "${pid}" 2>/dev/null || true
        fi
        local attempts=0
        while kill -0 "${pid}" 2>/dev/null && [ "${attempts}" -lt 50 ]; do
            # A zombie has already terminated; wait below reaps this owned child.
            [ "$(ps -o stat= -p "${pid}" 2>/dev/null | cut -c1)" != Z ] || break
            sleep 0.1
            attempts=$((attempts + 1))
        done
        if kill -0 "${pid}" 2>/dev/null && [ "$(ps -o stat= -p "${pid}" 2>/dev/null | cut -c1)" != Z ]; then
            echo "[!] ${name} exceeded graceful shutdown deadline"
            kill -KILL "${pid}" 2>/dev/null || true
        fi
        wait "${pid}" 2>/dev/null || true
    fi
}

stop_electron_cash() {
    local supervisor_pid=${ELECTRONCASH_PID}
    if [ -z "${supervisor_pid}" ] || ! kill -0 "${supervisor_pid}" 2>/dev/null; then
        return
    fi

    echo "[*] Stopping Electron Cash gracefully"
    : > "${SHUTDOWN_MARKER}"
    local child_pids
    child_pids=$(pgrep -P "${supervisor_pid}" || true)
    if [ -n "${child_pids}" ]; then
        kill -TERM ${child_pids} 2>/dev/null || true
    else
        kill -TERM "${supervisor_pid}" 2>/dev/null || true
    fi

    local attempts=0
    while kill -0 "${supervisor_pid}" 2>/dev/null && [ "${attempts}" -lt 50 ]; do
        sleep 0.2
        attempts=$((attempts + 1))
    done

    if kill -0 "${supervisor_pid}" 2>/dev/null; then
        kill -TERM "${supervisor_pid}" 2>/dev/null || true
        sleep 1
        kill -KILL ${child_pids} "${supervisor_pid}" 2>/dev/null || true
    fi
}

cleanup() {
    stop_electron_cash
    kill_gracefully "${X11VNC_PID}" "x11vnc"
    kill_gracefully "${WEBSOCKIFY_PID}" "websockify"
    # Display consumers must not keep cleanup waiting on the server they use.
    # The wallet and VNC clients are already stopped; close the owned display
    # before reaping the window manager's normal X11-disconnection exit.
    kill_gracefully "${XVFB_PID}" "Xvfb"
    kill_gracefully "${OPENBOX_PID}" "openbox"
}

trap cleanup EXIT
trap 'exit 1' SIGTERM SIGINT

wait_for_port() {
    local host=$1
    local port=$2
    local name=$3
    local attempts=0
    while ! timeout 1 bash -c "echo > /dev/tcp/${host}/${port}" 2>/dev/null; do
        attempts=$((attempts + 1))
        if [ "${attempts}" -ge 20 ]; then
            echo "[!] ${name} did not become ready on ${host}:${port}"
            return 1
        fi
        sleep 1
    done
    echo "[+] ${name} ready on ${host}:${port}"
}

verify_wallet_root() {
    if ! mountpoint -q "${WALLET_ROOT}"; then
        echo "[!] wallet data path is not a mounted Docker volume"
        return 1
    fi
    if [ -L "${WALLET_ROOT}" ] || [ ! -d "${WALLET_ROOT}" ]; then
        echo "[!] wallet data path must be a directory and must not be a symbolic link"
        return 1
    fi

    local symlink_entry
    symlink_entry=$(find -P "${WALLET_ROOT}" -xdev -type l -print -quit) || {
        echo "[!] unable to inspect wallet volume"
        return 1
    }
    if [ -n "${symlink_entry}" ]; then
        echo "[!] wallet data must not contain symbolic links: ${symlink_entry}"
        return 1
    fi

    if [ -L "${WALLET_MARKER}" ] || [ ! -f "${WALLET_MARKER}" ] || \
        ! printf '%s\n' "${EXPECTED_MARKER}" | cmp -s - "${WALLET_MARKER}"; then
        echo "[!] invalid wallet data marker"
        return 1
    fi

    if [ "$(stat -c '%u:%g' "${WALLET_ROOT}")" != "10001:10001" ] || \
        [ "$(stat -c '%a' "${WALLET_ROOT}")" != "700" ]; then
        echo "[!] wallet volume root ownership or mode is invalid"
        return 1
    fi
    if [ "$(stat -c '%u:%g' "${WALLET_MARKER}")" != "10001:10001" ] || \
        [ "$(stat -c '%a' "${WALLET_MARKER}")" != "600" ]; then
        echo "[!] wallet marker ownership or mode is invalid"
        return 1
    fi

    local incompatible_entry
    incompatible_entry=$(find -P "${WALLET_ROOT}" -xdev -mindepth 1 \
        \( ! -uid 10001 -o ! -gid 10001 \) -print -quit) || {
        echo "[!] unable to validate wallet data ownership"
        return 1
    }
    if [ -n "${incompatible_entry}" ]; then
        echo "[!] wallet data ownership does not match 10001:10001: ${incompatible_entry}"
        return 1
    fi
    if [ ! -r "${WALLET_MARKER}" ] || [ ! -w "${WALLET_ROOT}" ]; then
        echo "[!] wallet data is not effectively accessible by electroncash"
        return 1
    fi
}

ensure_config() {
    mkdir -p "${CONFIG_DIR}"
    CONFIG_FILE="${CONFIG_FILE}" USE_TOR="${USE_TOR}" EC_LANGUAGE="${EC_LANGUAGE}" python3 - <<'PY'
import json
import os
import tempfile
from gui_startup import theme_from_environment

path = os.environ["CONFIG_FILE"]
directory = os.path.dirname(path) or "."
try:
    with open(path) as handle:
        config = json.load(handle)
except FileNotFoundError:
    config = {"language": os.environ["EC_LANGUAGE"]}

config.setdefault("auto_connect", True)
config["qt_gui_color_theme"] = theme_from_environment()
if os.environ["USE_TOR"] == "true":
    config["proxy"] = "socks5:tor-proxy:9050"
else:
    config["proxy"] = "none"

fd, temporary_path = tempfile.mkstemp(prefix=".config.", dir=directory)
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=4, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)
finally:
    if os.path.exists(temporary_path):
        os.unlink(temporary_path)
PY
}

configure_jsonrpc() {
    CONFIG_FILE="${CONFIG_FILE}" \
    JSONRPC_ENABLED="${JSONRPC_ENABLED}" \
    JSONRPC_USER="${JSONRPC_USER}" \
    JSONRPC_PASSWORD="${JSONRPC_PASSWORD}" \
    JSONRPC_PORT="${JSONRPC_PORT}" \
        python3 - <<'PY'
import json
import os
import tempfile

path = os.environ["CONFIG_FILE"]
directory = os.path.dirname(path) or "."
with open(path) as handle:
    config = json.load(handle)

if os.environ["JSONRPC_ENABLED"] == "true":
    config["rpcuser"] = os.environ["JSONRPC_USER"]
    config["rpcpassword"] = os.environ["JSONRPC_PASSWORD"]
    config["rpcport"] = int(os.environ["JSONRPC_PORT"])
    # The host-side Compose mapping is the public exposure boundary. The
    # daemon must listen on the container interface to be reachable there.
    config["rpchost"] = "0.0.0.0"
else:
    # Keep Electron Cash's local daemon transport disabled without retaining
    # any credential value in the persisted configuration.
    config["rpcuser"] = ""
    config["rpcpassword"] = ""
    config["rpcport"] = 0
    config["rpchost"] = "127.0.0.1"

fd, temporary_path = tempfile.mkstemp(prefix=".config.", dir=directory)
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=4, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)
finally:
    if os.path.exists(temporary_path):
        os.unlink(temporary_path)
PY
}

preload_plugins() {
    local source_dir=/preinstalled-plugins
    local manifest=${source_dir}/plugins.json
    local destination_dir=${CONFIG_DIR}/external_plugins

    if [ ! -f "${manifest}" ]; then
        echo "[!] Trusted plugin manifest is missing from the image"
        return 1
    fi

    mkdir -p "${destination_dir}"
    PLUGIN_DATA=$(python3 - "${manifest}" <<'PY'
import json
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    plugins = json.load(handle).get("plugins")
if not isinstance(plugins, list) or not plugins:
    raise SystemExit("[!] Trusted plugin manifest is empty")
for plugin in plugins:
    package = plugin.get("package_name")
    version = plugin.get("version")
    digest = plugin.get("sha256")
    if not isinstance(package, str) or not package or not isinstance(version, str):
        raise SystemExit("[!] Trusted plugin manifest has invalid identity")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise SystemExit(f"[!] Trusted plugin {package} has an invalid SHA-256")
    if not isinstance(plugin.get("enabled"), bool):
        raise SystemExit(f"[!] Trusted plugin {package} has an invalid activation flag")
    print("\t".join((package, version, digest, str(plugin["enabled"]).lower())))
PY
)

    while IFS=$'\t' read -r package version expected_hash enabled; do
        [ -n "${package}" ] || continue
        local source_file="${source_dir}/${package}-${version}.zip"
        local destination_file="${destination_dir}/${package}-${version}.zip"
        if [ ! -f "${source_file}" ]; then
            echo "[!] Trusted plugin artifact is missing: ${source_file}"
            return 1
        fi
        if [ "$(sha256sum "${source_file}" | cut -d' ' -f1)" != "${expected_hash}" ]; then
            echo "[!] Trusted plugin artifact failed image verification: ${package}"
            return 1
        fi

        if [ -L "${destination_file}" ]; then
            rm -f "${destination_file}"
        elif [ -e "${destination_file}" ] && [ ! -f "${destination_file}" ]; then
            echo "[!] Plugin destination is not a regular file: ${destination_file}"
            return 1
        elif [ -f "${destination_file}" ] && \
            [ "$(sha256sum "${destination_file}" | cut -d' ' -f1)" != "${expected_hash}" ]; then
            echo "[!] Removing unverified existing plugin: ${destination_file}"
            rm -f "${destination_file}"
        fi

        if [ ! -f "${destination_file}" ]; then
            local temporary_file="${destination_file}.tmp.$$"
            cp "${source_file}" "${temporary_file}"
            if [ "$(sha256sum "${temporary_file}" | cut -d' ' -f1)" != "${expected_hash}" ]; then
                rm -f "${temporary_file}"
                echo "[!] Plugin copy failed verification: ${package}"
                return 1
            fi
            chmod 600 "${temporary_file}"
            mv -f "${temporary_file}" "${destination_file}"
            echo "[+] Verified plugin installed: ${package} v${version}"
        fi
    done <<< "${PLUGIN_DATA}"

    CONFIG_FILE="${CONFIG_FILE}" PLUGIN_MANIFEST="${manifest}" python3 - <<'PY'
import json
import os
import tempfile

config_path = os.environ["CONFIG_FILE"]
with open(config_path) as handle:
    config = json.load(handle)
with open(os.environ["PLUGIN_MANIFEST"]) as handle:
    manifest = json.load(handle)

changed = False
for plugin in manifest["plugins"]:
    key = "use_external_" + plugin["package_name"]
    if plugin["enabled"] and config.get(key) is not True:
        config[key] = True
        changed = True
if changed:
    directory = os.path.dirname(config_path) or "."
    fd, temporary_path = tempfile.mkstemp(prefix=".config.", dir=directory)
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
PY
}

ensure_test_wallet() {
    if [ "${WALLET_AUTO_CREATE}" != "true" ]; then
        return 0
    fi

    mkdir -p "$(dirname "${WALLET_FILE}")"

    if [ ! -f "${WALLET_FILE}" ]; then
        local cli=(/opt/electroncash-venv/bin/python /opt/electroncash-venv/bin/electron-cash)
        local create_args
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            echo "[*] Creating encrypted Chipnet wallet"
            create_args=(create -W "${TEST_WALLET_PASSWORD}" --encrypt_file)
        else
            echo "[*] Creating unencrypted Chipnet wallet"
            create_args=(create -W "")
        fi
        create_args+=("${EC_NET_FLAG[@]}")
        create_args+=(--wallet_path "${WALLET_FILE}")
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            if ! printf '%s\n%s\n' "${TEST_WALLET_PASSWORD}" "${TEST_WALLET_PASSWORD}" \
                | "${cli[@]}" "${create_args[@]}" >/dev/null 2>&1; then
                echo "[!] Failed to create encrypted Chipnet wallet"
                return 1
            fi
        else
            if ! printf '\n' | "${cli[@]}" "${create_args[@]}" >/dev/null 2>&1; then
                echo "[!] Failed to create Chipnet wallet"
                return 1
            fi
        fi
        echo "[+] Chipnet wallet created (seed suppressed from logs)"
    else
        echo "[+] Chipnet wallet found"
    fi

    CONFIG_FILE="${CONFIG_FILE}" WALLET_FILE="${WALLET_FILE}" python3 - <<'PY'
import json
import os
import tempfile

path = os.environ["CONFIG_FILE"]
directory = os.path.dirname(path) or "."
with open(path) as handle:
    config = json.load(handle)
config["gui_last_wallet"] = os.environ["WALLET_FILE"]
fd, temporary_path = tempfile.mkstemp(prefix=".config.", dir=directory)
try:
    with os.fdopen(fd, "w") as handle:
        json.dump(config, handle, indent=4, sort_keys=True)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_path, 0o600)
    os.replace(temporary_path, path)
finally:
    if os.path.exists(temporary_path):
        os.unlink(temporary_path)
PY
    chmod 600 "${CONFIG_FILE}" "${WALLET_FILE}"
}

start_headless() {
    echo "[*] Starting Electron Cash daemon without the GUI stack"
    local command=(/opt/electroncash-venv/bin/python /home/electroncash/electroncash-daemon-wrapper.py)
    command+=("${EC_NET_FLAG[@]}")
    if [ -f "${WALLET_FILE}" ]; then
        command+=(--wallet "${WALLET_FILE}")
    fi
    command+=("${EC_EXTRA_ARGS[@]}" daemon --verbose)
    env CASHFUSION_ENABLED="${CASHFUSION_ENABLED}" "${command[@]}" &
    ELECTRONCASH_PID=$!

    local cli=(/opt/electroncash-venv/bin/electron-cash)
    cli+=("${EC_NET_FLAG[@]}")
    local attempts=0
    while ! /opt/electroncash-venv/bin/python /home/electroncash/healthcheck.py >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "${attempts}" -ge 30 ]; then
            echo "[!] Electron Cash daemon did not become ready"
            return 1
        fi
        sleep 1
    done
    echo "[+] Electron Cash daemon ready"

    if [ -f "${WALLET_FILE}" ]; then
        local load_cli=("${cli[@]}")
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            # This short-lived CLI call is the only process that receives the
            # disposable test-wallet password; the daemon never gets it.
            load_cli+=(-wp "${TEST_WALLET_PASSWORD}")
        fi
        if "${load_cli[@]}" daemon load_wallet >/dev/null 2>&1; then
            echo "[+] Headless wallet loaded"
        elif [ -z "${TEST_WALLET_PASSWORD}" ] && /opt/electroncash-venv/bin/python - "${WALLET_FILE}" <<'PY' >/dev/null 2>&1
from electroncash.storage import WalletStorage
import sys

storage = WalletStorage(sys.argv[1], manual_upgrades=True)
raise SystemExit(0 if storage.is_encrypted() else 1)
PY
        then
            echo "[*] Encrypted production wallet requires operator unlock"
        else
            echo "[!] Wallet could not be loaded by the headless daemon"
            return 1
        fi
    else
        echo "[*] No wallet supplied; encrypted production wallets remain operator-loaded"
    fi
}

start_novnc() {
    echo "[*] Starting ${ECD_PRODUCT_VERSION} noVNC wallet"

    Xvfb :99 -screen 0 1600x900x24 -nolisten tcp &
    XVFB_PID=$!
    local attempts=0
    while ! xdpyinfo -display :99 >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "${attempts}" -ge 20 ]; then
            echo "[!] Xvfb did not become ready"
            return 1
        fi
        sleep 1
    done

    openbox-session &
    OPENBOX_PID=$!
    x11vnc -display :99 -forever -shared -nopw -localhost -rfbport 5900 &
    X11VNC_PID=$!
    wait_for_port localhost 5900 "x11vnc" || return 1

    /usr/bin/python3 /home/electroncash/session-websockify.py --heartbeat 30 --web=/opt/noVNC 6080 localhost:5900 &
    WEBSOCKIFY_PID=$!
    wait_for_port localhost 6080 "noVNC" || return 1

    local command=(/opt/electroncash-venv/bin/python /home/electroncash/electroncash-wrapper.py)
    command+=("${EC_NET_FLAG[@]}")
    command+=("${EC_EXTRA_ARGS[@]}" --verbose)
    env CASHFUSION_ENABLED="${CASHFUSION_ENABLED}" DISPLAY=:99 "${command[@]}" &
    ELECTRONCASH_PID=$!
}

start_gui() {
    echo "[*] Starting ${ECD_PRODUCT_VERSION} on host X11 display ${DISPLAY}"
    local command=(/opt/electroncash-venv/bin/python /home/electroncash/electroncash-wrapper.py)
    command+=("${EC_NET_FLAG[@]}" "${EC_EXTRA_ARGS[@]}" --verbose)
    env CASHFUSION_ENABLED="${CASHFUSION_ENABLED}" "${command[@]}" &
    ELECTRONCASH_PID=$!
}

echo "=========================================="
echo "  Electron Cash Docker v${ECD_PRODUCT_VERSION}"
echo "  Mode:    ${MODE}"
echo "  Network: ${NETWORK_LABEL}"
echo "  Tor:     ${USE_TOR}"
echo "  Fusion:  ${CASHFUSION_ENABLED}"
if [ "${JSONRPC_ENABLED}" = "true" ]; then
    echo "  RPC:     enabled on port ${JSONRPC_PORT}"
else
    echo "  RPC:     disabled"
fi
echo "=========================================="

verify_wallet_root
if [ "${ECD_GUI_SESSION:-false}" = true ]; then
    /opt/electroncash-venv/bin/python /home/electroncash/gui_session.py
fi
mkdir -p "${XDG_RUNTIME_DIR}" "${HOME}/.local/share"
rm -f "${SHUTDOWN_MARKER}"
chmod 700 "${XDG_RUNTIME_DIR}"

ensure_config
ensure_test_wallet
configure_jsonrpc
CONFIG_FILE="${CONFIG_FILE}" /home/electroncash/cashfusion.sh
preload_plugins

case "${MODE}" in
    novnc) start_novnc ;;
    headless) start_headless ;;
    gui) start_gui ;;
esac

wallet_status=0
wait "${ELECTRONCASH_PID}" || wallet_status=$?
if [ "${MODE}" = novnc ] && [ "${ECD_GUI_SESSION:-false}" = true ]; then
    # Qt may fail during destructor teardown after its explicit aboutToQuit
    # event. That already-committed GUI end must not resurrect the session.
    # Unexpected crashes never publish this event and retain on-failure recovery.
    if /opt/electroncash-venv/bin/python -c 'from gui_session import read_state; import sys; state=read_state(); sys.exit(0 if state and state[1] == "ended" else 1)'; then
        echo "[+] Intentional GUI exit accepted (upstream status ${wallet_status})"
        wallet_status=0
    fi
fi
exit "${wallet_status}"
