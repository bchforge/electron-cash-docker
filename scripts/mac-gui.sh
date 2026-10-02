#!/bin/bash
# Local XQuartz transport for Docker Desktop. Only NETWORK selects the chain.
set -euo pipefail

PROJECT_DIR=$(CDPATH= cd "$(dirname "$0")/.." && pwd -P)
if [ "$(uname -s)" != Darwin ]; then
    echo "[!] XQuartz requires macOS" >&2; exit 1
fi
for tool in docker defaults open osascript pgrep ps xauth lsof python3; do
    command -v "$tool" >/dev/null || { echo "[!] missing prerequisite: $tool" >&2; exit 1; }
done
docker compose version >/dev/null || { echo "[!] Docker Compose v2 is required" >&2; exit 1; }
[ -d "${XQUARTZ_APP:-/Applications/Utilities/XQuartz.app}" ] || { echo "[!] install XQuartz first" >&2; exit 1; }
docker info >/dev/null || { echo "[!] start Docker Desktop first" >&2; exit 1; }
[ -f "$PROJECT_DIR/.env" ] || { echo "[!] configure $PROJECT_DIR/.env first" >&2; exit 1; }
export PATH="/opt/X11/bin:$PATH"

preflight_compose=(docker compose --project-directory "$PROJECT_DIR" \
    -f "$PROJECT_DIR/docker-compose.yml" -f "$PROJECT_DIR/docker-compose.gui.yml")
platform_override=${ECD_PLATFORM_OVERRIDE:-}
if [ -n "$platform_override" ]; then
    [ -f "$platform_override" ] && [ ! -L "$platform_override" ] || {
        echo "[!] platform override is missing or unsafe" >&2; exit 1;
    }
    python3 - "$platform_override" "$(uname -m)" <<'PY'
import json
import sys
from pathlib import Path

machine = sys.argv[2]
if machine in ("arm64", "aarch64"):
    tor_platform = "linux/arm64"
elif machine in ("x86_64", "amd64"):
    tor_platform = "linux/amd64"
else:
    raise SystemExit(f"[!] unsupported Mac architecture for the Tor helper: {machine}")
expected = {"services": {"electron-cash": {"platform": "linux/amd64"},
                         "tor-proxy": {"platform": tor_platform}}}
if json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")) != expected:
    raise SystemExit("[!] platform override does not match the supported Mac GUI image targets")
PY
    preflight_compose+=(-f "$platform_override")
fi
preflight_display=${DISPLAY:-:0}
preflight_authority=${XAUTHORITY:-$HOME/.Xauthority}
resolved_project=$(DISPLAY="$preflight_display" XAUTHORITY="$preflight_authority" \
    "${preflight_compose[@]}" config --format json | python3 -c 'import json,sys; print(json.load(sys.stdin).get("name", ""))')
case "$resolved_project" in ''|*[!A-Za-z0-9_.-]*)
    echo "[!] Unable to prove the XQuartz Compose project identity" >&2; exit 1 ;;
esac
existing_containers=$("${preflight_compose[@]}" ps -a -q)
existing_networks=$(docker network ls -q --filter "label=com.docker.compose.project=$resolved_project")
if [ -n "$existing_containers" ] || [ -n "$existing_networks" ]; then
    echo "[!] this Compose project already owns Docker resources; refusing XQuartz cleanup authority" >&2
    exit 1
fi

domain=org.xquartz.X11
original=$(defaults read "$domain" nolisten_tcp 2>/dev/null) && had_setting=true || { original=; had_setting=false; }
if [ "$had_setting" = true ]; then
    case "$original" in
        1|true|TRUE|yes|YES) original_bool=true ;;
        0|false|FALSE|no|NO) original_bool=false ;;
        *) echo "[!] unable to interpret the original XQuartz nolisten_tcp Boolean" >&2; exit 1 ;;
    esac
else
    # XQuartz defaults to TCP disabled when the preference is absent.
    original_bool=true
fi
was_running=false
xquartz_process=
xquartz_pid=
xquartz_started_pid=
xquartz_started_by_task=false
xquartz_lock_file=/tmp/.X0-lock
detect_xquartz_process() {
    local status pids
    if pids=$(pgrep -x X11); then
        xquartz_process=X11
        xquartz_pid=${pids%%$'\n'*}
        if [ "$xquartz_started_by_task" = true ]; then xquartz_started_pid=$xquartz_pid; fi
        return 0
    else status=$?; [ "$status" -eq 1 ] || return 2; fi
    if pids=$(pgrep -x X11.bin); then
        xquartz_process=X11.bin
        xquartz_pid=${pids%%$'\n'*}
        if [ "$xquartz_started_by_task" = true ]; then xquartz_started_pid=$xquartz_pid; fi
        return 0
    else status=$?; [ "$status" -eq 1 ] || return 2; fi
    xquartz_process=
    xquartz_pid=
    return 1
}
remove_stale_task_xquartz_lock() {
    local lock_pid process_args
    if [ ! -e "$xquartz_lock_file" ] && [ ! -L "$xquartz_lock_file" ]; then return 0; fi
    [ ! -L "$xquartz_lock_file" ] || { echo "[!] refusing to remove a symlinked XQuartz display lock" >&2; return 1; }
    lock_pid=$(<"$xquartz_lock_file")
    lock_pid=${lock_pid//[[:space:]]/}
    [ "$lock_pid" = "$xquartz_started_pid" ] || return 0
    process_args=$(ps -p "$lock_pid" -o args= 2>/dev/null || true)
    if [ -n "$process_args" ]; then
        echo "[!] refusing to remove XQuartz lock for a live PID" >&2
        return 1
    fi
    rm -f "$xquartz_lock_file"
}
mark_task_xquartz_stopped() {
    remove_stale_task_xquartz_lock || return 1
    xquartz_process=
    xquartz_pid=
    xquartz_started_pid=
    xquartz_started_by_task=false
}
if detect_xquartz_process; then
    was_running=true
else
    state=$?
    [ "$state" -eq 1 ] || { echo "[!] unable to determine whether XQuartz is running" >&2; exit 1; }
fi
changed=false
started=false
temporary=
mac_overlay=
stop_task_xquartz() {
    local attempt state process_args expected_binary
    if [ -z "$xquartz_process" ] && [ "$xquartz_started_by_task" != true ]; then return 0; fi
    if [ "$xquartz_started_by_task" = true ]; then
        expected_binary="${XQUARTZ_APP:-/Applications/Utilities/XQuartz.app}/Contents/MacOS/X11.bin"
        if [ -z "$xquartz_started_pid" ]; then
            if detect_xquartz_process; then xquartz_started_pid=$xquartz_pid; else
                state=$?
                if [ "$state" -eq 1 ]; then mark_task_xquartz_stopped; return $?; fi
                echo "[!] unable to verify task-started XQuartz process" >&2
                return 1
            fi
        fi
        process_args=$(ps -p "$xquartz_started_pid" -o args= 2>/dev/null || true)
        case "$process_args" in
            "$expected_binary"*) kill -TERM "$xquartz_started_pid" 2>/dev/null || true ;;
            *) echo "[!] refusing to signal a PID that no longer matches task-started XQuartz" >&2; return 1 ;;
        esac
        for ((attempt=0; attempt<10; attempt++)); do
            if detect_xquartz_process; then sleep 0.2; else
                state=$?
                if [ "$state" -eq 1 ]; then mark_task_xquartz_stopped; return $?; fi
                echo "[!] unable to verify XQuartz shutdown" >&2
                return 1
            fi
        done
        process_args=$(ps -p "$xquartz_started_pid" -o args= 2>/dev/null || true)
        case "$process_args" in
            "$expected_binary"*) kill -KILL "$xquartz_started_pid" 2>/dev/null || true ;;
            *) echo "[!] refusing to force-stop a PID that no longer matches task-started XQuartz" >&2; return 1 ;;
        esac
        for ((attempt=0; attempt<10; attempt++)); do
            if detect_xquartz_process; then sleep 0.2; else
                state=$?
                if [ "$state" -eq 1 ]; then mark_task_xquartz_stopped; return $?; fi
                echo "[!] unable to verify XQuartz shutdown" >&2
                return 1
            fi
        done
        echo "[!] task-started XQuartz process did not stop" >&2
        return 1
    fi
    osascript -e 'tell application id "org.xquartz.X11" to quit' || true
    for ((attempt=0; attempt<50; attempt++)); do
        if detect_xquartz_process; then
            sleep 0.2
        else
            state=$?
            if [ "$state" -eq 1 ]; then xquartz_process=; xquartz_pid=; return 0; fi
            echo "[!] unable to verify XQuartz shutdown" >&2
            return 1
        fi
    done
    echo "[!] task-started XQuartz process did not stop" >&2
    return 1
}
restore_tcp_setting() {
    local attempt=1 current=
    while [ "$attempt" -le 3 ]; do
        if [ "$had_setting" = true ]; then
            defaults write "$domain" nolisten_tcp -bool "$original_bool" || true
            current=$(defaults read "$domain" nolisten_tcp 2>/dev/null || true)
            if { [ "$original_bool" = true ] && [ "$current" = 1 ]; } || \
               { [ "$original_bool" = false ] && [ "$current" = 0 ]; }; then return 0; fi
        else
            defaults delete "$domain" nolisten_tcp 2>/dev/null || true
            if ! defaults read "$domain" nolisten_tcp >/dev/null 2>&1; then return 0; fi
        fi
        attempt=$((attempt + 1))
        sleep 1
    done
    if [ "$had_setting" = true ]; then
        recovery="defaults write $domain nolisten_tcp -bool $original_bool"
    else
        recovery="defaults delete $domain nolisten_tcp"
    fi
    echo "[!] Could not restore XQuartz nolisten_tcp; XQuartz will remain stopped. Restore manually with: $recovery" >&2
    return 1
}
cleanup() {
    local result=$?
    trap - EXIT INT TERM
    if [ "$started" = true ]; then
        if [ "${CI_DOCKER_OWNER_SHIM:-0}" = 1 ] &&
           [ -n "${CI_RESOURCE_OWNER:-}" ] && [ -n "${CI_RESOURCE_REGISTRY:-}" ]; then
            echo "[*] Docker resource cleanup is delegated to the owner-checked platform runner."
        else
            local cleanup_compose=(docker compose --project-directory "$PROJECT_DIR" \
                -f "$PROJECT_DIR/docker-compose.yml" -f "$PROJECT_DIR/docker-compose.gui.yml")
            if [ -n "$platform_override" ]; then cleanup_compose+=(-f "$platform_override"); fi
            if [ -n "$mac_overlay" ] && [ -f "$mac_overlay" ]; then cleanup_compose+=(-f "$mac_overlay"); fi
            "${cleanup_compose[@]}" down --remove-orphans || result=1
        fi
    fi
    if [ "$changed" = true ]; then
        stop_ok=true
        stop_task_xquartz || { stop_ok=false; result=1; }
        restore_ok=true
        restore_tcp_setting || { restore_ok=false; result=1; }
        # XQuartz reads this preference at launch, so restart only the detected
        # X11/X11.bin process when the runner changed the TCP setting.
        if [ "$was_running" = true ] && [ "$restore_ok" = true ] && [ "$stop_ok" = true ]; then
            open -a XQuartz || result=1
            restored=false
            for ((attempt=0; attempt<30; attempt++)); do
                if detect_xquartz_process; then restored=true; break; fi
                state=$?
                if [ "$state" -ne 1 ]; then result=1; break; fi
                sleep 1
            done
            [ "$restored" = true ] || result=1
        fi
    elif [ "$was_running" = false ]; then
        # XQuartz was stopped before this check, so only its process started by
        # this launcher is eligible for shutdown.
        stop_task_xquartz || result=1
    fi
    if [ -n "$temporary" ]; then rm -rf "$temporary"; fi
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "$original_bool" = true ]; then
    echo "[*] Temporarily enabling XQuartz TCP; existing XQuartz sessions will restart."
    changed=true
    defaults write "$domain" nolisten_tcp -bool false
    if [ "$was_running" = true ]; then stop_task_xquartz; fi
fi
xquartz_started_by_task=true
open -a XQuartz
for ((attempt=0; attempt<30; attempt++)); do
    if detect_xquartz_process && lsof -nP -iTCP:6000 -sTCP:LISTEN >/dev/null; then break; fi
    state=$?
    if [ "$state" -gt 1 ]; then echo "[!] unable to determine whether XQuartz is running" >&2; exit 1; fi
    sleep 1
done
[ -n "$xquartz_process" ] || { echo "[!] XQuartz server did not start" >&2; exit 1; }
lsof -nP -iTCP:6000 -sTCP:LISTEN >/dev/null || { echo "[!] XQuartz TCP :6000 did not start" >&2; exit 1; }

host_display=${DISPLAY:-:0}
xauth_displays=("$host_display")
case "$host_display" in */org.xquartz:*) xauth_displays+=("${host_display##*/org.xquartz}");; esac
cookie_record=
authority_error=false
for candidate_display in "${xauth_displays[@]}"; do
    if ! auth_listing=$(xauth list "$candidate_display" 2>/dev/null); then
        authority_error=true
        continue
    fi
    case "$auth_listing" in *" MIT-MAGIC-COOKIE-1 "*) ;; *) continue ;; esac
    if ! candidate_record=$(xauth nlist "$candidate_display" 2>/dev/null); then
        authority_error=true
        continue
    fi
    if [ -n "$candidate_record" ]; then
        cookie_record=$candidate_record
        break
    fi
done
if [ -z "$cookie_record" ]; then
    if [ "$authority_error" = true ]; then
        echo "[!] unable to read XQuartz MIT-MAGIC-COOKIE-1 authority for DISPLAY=$host_display" >&2
    else
        echo "[!] no usable XQuartz MIT-MAGIC-COOKIE-1 authority for DISPLAY=$host_display" >&2
    fi
    exit 1
fi
temporary=$(mktemp -d /tmp/ecd-xquartz.XXXXXXXX)
chmod 700 "$temporary"
# FamilyWild avoids depending on host.docker.internal DNS on the Mac; only
# the wallet container receives this short-lived cookie file, not xhost access.
printf '%s\n' "$cookie_record" | while IFS= read -r record; do
    [ -n "$record" ] || continue
    printf 'ffff%s\n' "${record:4}"
done | xauth -f "$temporary/authority" nmerge -
chmod 644 "$temporary/authority"
export XAUTHORITY="$temporary/authority"
export DISPLAY=host.docker.internal:0
mac_overlay=${temporary}/mac-compose.yml
python3 "$PROJECT_DIR/scripts/mac-compose-overlay.py" "$mac_overlay" "$XAUTHORITY"
compose=(docker compose --project-directory "$PROJECT_DIR" -f "$PROJECT_DIR/docker-compose.yml" \
    -f "$PROJECT_DIR/docker-compose.gui.yml" -f "$mac_overlay")
if [ -n "$platform_override" ]; then
    compose=(docker compose --project-directory "$PROJECT_DIR" -f "$PROJECT_DIR/docker-compose.yml" \
        -f "$PROJECT_DIR/docker-compose.gui.yml" -f "$platform_override" -f "$mac_overlay")
fi
if [ -n "$("${compose[@]}" ps -a -q)" ]; then
    echo "[!] this Compose project already has containers; stop or remove them before XQuartz mode" >&2; exit 1
fi
if [ -n "$(docker network ls -q --filter "label=com.docker.compose.project=$resolved_project")" ]; then
    echo "[!] this Compose project already has a network; refusing XQuartz cleanup authority" >&2; exit 1
fi
echo "[*] Launching native XQuartz GUI; close the wallet window to stop."
started=true
if [ "${ECD_PLATFORM_IMAGE_BUILD_DONE:-false}" = true ] || [ "${ECD_PLATFORM_IMAGE_BUILD_DONE:-false}" = 1 ]; then
    "${compose[@]}" up -d --no-build --no-deps tor-proxy
else
    "${compose[@]}" up -d --build --no-deps tor-proxy
fi
"${compose[@]}" up --no-build --no-deps electron-cash
