#!/bin/bash

set -euo pipefail

export HOME=/home/electroncash
export DISPLAY=:99
export XDG_RUNTIME_DIR=/tmp/runtime-electroncash

USE_TOR=${USE_TOR}
TESTNET4=${TESTNET4:-false}
WALLET_AUTO_CREATE=${WALLET_AUTO_CREATE:-false}
TEST_WALLET_PASSWORD=${TEST_WALLET_PASSWORD:-}
ELECTRONCASH_RUNTIME=${ELECTRONCASH_RUNTIME:-false}

case "${USE_TOR}" in
    true|false) ;;
    *) echo "[!] USE_TOR must be true or false"; exit 1 ;;
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

readonly WALLET_ROOT=/home/electroncash/.electron-cash
readonly WALLET_MARKER=${WALLET_ROOT}/.electron-cash-docker
readonly EXPECTED_MARKER=electron-cash-docker-v0.1

case "${TESTNET4}" in
    true)
        EC_NET_FLAG="--testnet4"
        NETWORK_LABEL=testnet4
        CONFIG_DIR="${WALLET_ROOT}/testnet4"
        ;;
    false)
        EC_NET_FLAG=""
        NETWORK_LABEL=mainnet
        CONFIG_DIR="${WALLET_ROOT}"
        ;;
    *)
        echo "[!] TESTNET4 must be true or false"
        exit 1
        ;;
esac
CONFIG_FILE="${CONFIG_DIR}/config"
WALLET_FILE="${CONFIG_DIR}/wallets/default_wallet"

if [ "${TESTNET4}" != "true" ] && {
    [ "${WALLET_AUTO_CREATE}" = "true" ] || [ -n "${TEST_WALLET_PASSWORD}" ];
}; then
    echo "[!] WALLET_AUTO_CREATE and TEST_WALLET_PASSWORD are testnet4-only"
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
    exec setpriv --reuid 10001 --regid 10001 --clear-groups -- \
        env ELECTRONCASH_RUNTIME=true HOME=/home/electroncash \
        DISPLAY=:99 XDG_RUNTIME_DIR=/tmp/runtime-electroncash "$0" "$@"
fi

if [ "$(id -u)" -ne 10001 ] || [ "$(id -g)" -ne 10001 ]; then
    echo "[!] Electron Cash runtime must use UID/GID 10001:10001"
    exit 1
fi

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
        kill -TERM "${pid}" 2>/dev/null || true
        sleep 1
        kill -KILL "${pid}" 2>/dev/null || true
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
    kill_gracefully "${WEBSOCKIFY_PID}" "websockify"
    kill_gracefully "${X11VNC_PID}" "x11vnc"
    kill_gracefully "${OPENBOX_PID}" "openbox"
    kill_gracefully "${XVFB_PID}" "Xvfb"
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
    CONFIG_FILE="${CONFIG_FILE}" USE_TOR="${USE_TOR}" python3 - <<'PY'
import json
import os
import tempfile

path = os.environ["CONFIG_FILE"]
directory = os.path.dirname(path) or "."
try:
    with open(path) as handle:
        config = json.load(handle)
except FileNotFoundError:
    config = {}

config.setdefault("auto_connect", True)
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

ensure_test_wallet() {
    if [ "${WALLET_AUTO_CREATE}" != "true" ]; then
        return 0
    fi

    mkdir -p "$(dirname "${WALLET_FILE}")"

    if [ ! -f "${WALLET_FILE}" ]; then
        local cli=(/opt/electroncash-venv/bin/python /opt/electroncash-venv/bin/electron-cash)
        local create_args
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            echo "[*] Creating encrypted testnet4 wallet"
            create_args=(create -W "${TEST_WALLET_PASSWORD}" --encrypt_file)
        else
            echo "[*] Creating unencrypted testnet4 wallet"
            create_args=(create -W "")
        fi
        if [ -n "${EC_NET_FLAG}" ]; then
            create_args+=("${EC_NET_FLAG}")
        fi
        create_args+=(--wallet_path "${WALLET_FILE}")
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            if ! printf '%s\n%s\n' "${TEST_WALLET_PASSWORD}" "${TEST_WALLET_PASSWORD}" \
                | "${cli[@]}" "${create_args[@]}" >/dev/null 2>&1; then
                echo "[!] Failed to create encrypted testnet4 wallet"
                return 1
            fi
        else
            if ! printf '\n' | "${cli[@]}" "${create_args[@]}" >/dev/null 2>&1; then
                echo "[!] Failed to create testnet4 wallet"
                return 1
            fi
        fi
        echo "[+] Testnet4 wallet created (seed suppressed from logs)"
    else
        echo "[+] Testnet4 wallet found"
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

start_novnc() {
    echo "[*] Starting v0.1 noVNC wallet"

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
    x11vnc -display :99 -forever -alwaysshared -nopw -rfbport 5900 &
    X11VNC_PID=$!
    wait_for_port localhost 5900 "x11vnc" || return 1

    websockify --web=/opt/noVNC 6080 localhost:5900 &
    WEBSOCKIFY_PID=$!
    wait_for_port localhost 6080 "noVNC" || return 1

    local command=(/opt/electroncash-venv/bin/python /home/electroncash/electroncash-wrapper.py)
    if [ -n "${EC_NET_FLAG}" ]; then
        command+=("${EC_NET_FLAG}")
    fi
    command+=(--verbose)
    env DISPLAY=:99 "${command[@]}" &
    ELECTRONCASH_PID=$!
}

echo "=========================================="
echo "  Electron Cash Docker v0.1"
echo "  Network: ${NETWORK_LABEL}"
echo "  Tor:     ${USE_TOR}"
echo "  Fusion:  ${CASHFUSION_ENABLED}"
echo "  AutoFuse:${CASHFUSION_AUTO_FUSE:-false}"
echo "=========================================="

verify_wallet_root
mkdir -p "${XDG_RUNTIME_DIR}" "${HOME}/.local/share"
rm -f "${SHUTDOWN_MARKER}"
chmod 700 "${XDG_RUNTIME_DIR}"

ensure_config
ensure_test_wallet
CONFIG_FILE="${CONFIG_FILE}" /home/electroncash/cashfusion.sh
start_novnc

wait "${ELECTRONCASH_PID}"
