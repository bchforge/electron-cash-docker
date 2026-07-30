#!/bin/bash

set -euo pipefail

export DISPLAY=:99
export XDG_RUNTIME_DIR=/tmp/runtime-ubuntu

USE_TOR=${USE_TOR}
WALLET_DIR_HOST=${WALLET_DIR_HOST:-}
TESTNET4=${TESTNET4:-false}
WALLET_AUTO_CREATE=${WALLET_AUTO_CREATE:-false}
TEST_WALLET_PASSWORD=${TEST_WALLET_PASSWORD:-}

case "${USE_TOR}" in
    true|false) ;;
    *) echo "[!] USE_TOR must be true or false"; exit 1 ;;
esac
if [ -n "${WALLET_DIR_HOST}" ]; then
    WALLET_DIR_NAME=${WALLET_DIR_HOST%/}
    WALLET_DIR_NAME=${WALLET_DIR_NAME##*/}
    case "${WALLET_DIR_NAME}" in
        ""|.|..) echo "[!] WALLET_DIR must reference a dedicated wallet directory"; exit 1 ;;
    esac
fi
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

WALLET_ROOT=/home/ubuntu/.electron-cash
WALLET_MARKER=${WALLET_ROOT}/.electron-cash-docker
case "$TESTNET4" in
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

if [ "${TESTNET4}" != "true" ] && { [ "${WALLET_AUTO_CREATE}" = "true" ] || [ -n "${TEST_WALLET_PASSWORD}" ]; }; then
    echo "[!] WALLET_AUTO_CREATE and TEST_WALLET_PASSWORD are testnet4-only"
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
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "[*] Stopping ${name}"
        kill -TERM "$pid" 2>/dev/null || true
        sleep 1
        kill -KILL "$pid" 2>/dev/null || true
    fi
}

stop_electron_cash() {
    local supervisor_pid=$ELECTRONCASH_PID
    if [ -z "$supervisor_pid" ] || ! kill -0 "$supervisor_pid" 2>/dev/null; then
        return
    fi

    echo "[*] Stopping Electron Cash gracefully"
    : > "$SHUTDOWN_MARKER"
    local child_pids
    child_pids=$(pgrep -P "$supervisor_pid" || true)
    if [ -n "$child_pids" ]; then
        kill -TERM $child_pids 2>/dev/null || true
    else
        kill -TERM "$supervisor_pid" 2>/dev/null || true
    fi

    local attempts=0
    while kill -0 "$supervisor_pid" 2>/dev/null && [ "$attempts" -lt 50 ]; do
        sleep 0.2
        attempts=$((attempts + 1))
    done

    if kill -0 "$supervisor_pid" 2>/dev/null; then
        kill -TERM "$supervisor_pid" 2>/dev/null || true
        sleep 1
        kill -KILL $child_pids "$supervisor_pid" 2>/dev/null || true
    fi
}

cleanup() {
    stop_electron_cash
    kill_gracefully "$WEBSOCKIFY_PID" "websockify"
    kill_gracefully "$X11VNC_PID" "x11vnc"
    kill_gracefully "$OPENBOX_PID" "openbox"
    kill_gracefully "$XVFB_PID" "Xvfb"
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
        if [ "$attempts" -ge 20 ]; then
            echo "[!] ${name} did not become ready on ${host}:${port}"
            return 1
        fi
        sleep 1
    done
    echo "[+] ${name} ready on ${host}:${port}"
}

initialize_wallet_root() {
    mkdir -p "${WALLET_ROOT}"

    local symlink_entry
    symlink_entry=$(find -P "${WALLET_ROOT}" -type l -print -quit)
    if [ -n "${symlink_entry}" ]; then
        echo "[!] WALLET_DIR must not contain symbolic links: ${symlink_entry}"
        return 1
    fi

    if [ -e "${WALLET_MARKER}" ]; then
        if [ ! -f "${WALLET_MARKER}" ] || ! grep -qx 'electron-cash-docker-v0.1' "${WALLET_MARKER}"; then
            echo "[!] Invalid wallet directory marker"
            return 1
        fi
    else
        local existing_entry
        existing_entry=$(find "${WALLET_ROOT}" -mindepth 1 -maxdepth 1 -print -quit)
        if [ -n "${existing_entry}" ]; then
            echo "[!] WALLET_DIR must be empty on first use or already initialized by Electron Cash Docker"
            return 1
        fi
        printf '%s\n' 'electron-cash-docker-v0.1' > "${WALLET_MARKER}"
    fi

    chown ubuntu:ubuntu "${WALLET_ROOT}" "${WALLET_MARKER}"
    chmod 700 "${WALLET_ROOT}"
    chmod 600 "${WALLET_MARKER}"

    local incompatible_entry
    incompatible_entry=$(find "${WALLET_ROOT}" -mindepth 1 \
        ! -path "${WALLET_MARKER}" \( ! -user ubuntu -o ! -group ubuntu \) \
        -print -quit)
    if [ -n "${incompatible_entry}" ]; then
        echo "[!] Wallet data ownership does not match the configured UID/GID: ${incompatible_entry}"
        return 1
    fi
}

ensure_config() {
    su ubuntu -c "mkdir -p '${CONFIG_DIR}'"
    su ubuntu -c "CONFIG_FILE='${CONFIG_FILE}' USE_TOR='${USE_TOR}' python3 -" <<'PY'
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

    su ubuntu -c "mkdir -p '$(dirname "${WALLET_FILE}")'"

    if [ ! -f "${WALLET_FILE}" ]; then
        local cli="/opt/electroncash-venv/bin/python /opt/electroncash-venv/bin/electron-cash"
        if [ -n "${TEST_WALLET_PASSWORD}" ]; then
            echo "[*] Creating encrypted testnet4 wallet"
            if ! printf '%s\n%s\n' "${TEST_WALLET_PASSWORD}" "${TEST_WALLET_PASSWORD}" \
                | su ubuntu -c "${cli} create -W '${TEST_WALLET_PASSWORD}' --encrypt_file ${EC_NET_FLAG} --wallet_path '${WALLET_FILE}'" \
                    >/dev/null 2>&1; then
                echo "[!] Failed to create encrypted testnet4 wallet"
                return 1
            fi
        else
            echo "[*] Creating unencrypted testnet4 wallet"
            if ! printf '\n' | su ubuntu -c "${cli} create -W '' ${EC_NET_FLAG} --wallet_path '${WALLET_FILE}'" \
                >/dev/null 2>&1; then
                echo "[!] Failed to create testnet4 wallet"
                return 1
            fi
        fi
        echo "[+] Testnet4 wallet created (seed suppressed from logs)"
    else
        echo "[+] Testnet4 wallet found"
    fi

    su ubuntu -c "CONFIG_FILE='${CONFIG_FILE}' WALLET_FILE='${WALLET_FILE}' python3 -" <<'PY'
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

    su ubuntu -c "Xvfb :99 -screen 0 1600x900x24 -nolisten tcp" &
    XVFB_PID=$!
    local attempts=0
    while ! su ubuntu -c "xdpyinfo -display :99" >/dev/null 2>&1; do
        attempts=$((attempts + 1))
        if [ "$attempts" -ge 20 ]; then
            echo "[!] Xvfb did not become ready"
            return 1
        fi
        sleep 1
    done

    su ubuntu -c "openbox-session" &
    OPENBOX_PID=$!
    su ubuntu -c "x11vnc -display :99 -forever -alwaysshared -nopw -rfbport 5900" &
    X11VNC_PID=$!
    wait_for_port localhost 5900 "x11vnc" || return 1

    su ubuntu -c "websockify --web=/opt/noVNC 6080 localhost:5900" &
    WEBSOCKIFY_PID=$!
    wait_for_port localhost 6080 "noVNC" || return 1

    local command="/opt/electroncash-venv/bin/python /home/ubuntu/electroncash-wrapper.py"
    if [ -n "${EC_NET_FLAG}" ]; then
        command="${command} ${EC_NET_FLAG}"
    fi
    command="${command} --verbose"
    su ubuntu -c "trap - INT; exec env DISPLAY=:99 ${command}" &
    ELECTRONCASH_PID=$!
}

echo "=========================================="
echo "  Electron Cash Docker v0.1"
echo "  Network: ${NETWORK_LABEL}"
echo "  Tor:     ${USE_TOR}"
echo "  Fusion:  ${CASHFUSION_ENABLED}"
echo "  AutoFuse:${CASHFUSION_AUTO_FUSE:-false}"
echo "=========================================="

initialize_wallet_root
mkdir -p "/tmp/runtime-ubuntu" "/home/ubuntu/.local/share"
rm -f "$SHUTDOWN_MARKER"
chown ubuntu:ubuntu "/tmp/runtime-ubuntu" "/home/ubuntu/.local/share"
chmod 700 "/tmp/runtime-ubuntu"

ensure_config
ensure_test_wallet
su ubuntu -c "CONFIG_FILE='${CONFIG_FILE}' /home/ubuntu/cashfusion.sh"
start_novnc

wait "${ELECTRONCASH_PID}"
