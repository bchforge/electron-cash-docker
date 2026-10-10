#!/bin/sh
# Supervise only this container's command/process group. No Docker daemon access.
set -eu
if [ "${ECD_GUI_SESSION:-false}" != true ]; then
    exec "$@"
fi
setsid "$@" &
child=$!
echo "[+] GUI lifecycle supervisor owns child $child"
stopping=false
stop_deadline=0
terminate() {
    if [ "$stopping" = true ]; then return; fi
    stopping=true
    stop_deadline=$(( $(date +%s) + 8 ))
    echo "[*] GUI supervisor terminating owned child $child"
    # One signal to the owned session, not two to its leader. The fallback
    # covers an external stop arriving before setsid has created the group.
    kill -TERM "-$child" 2>/dev/null || kill -TERM "$child" || true
}
trap terminate TERM INT
ended=false
deadline=0
while kill -0 "$child" 2>/dev/null; do
    if [ "$stopping" = true ]; then
        if [ "$(date +%s)" -ge "$stop_deadline" ]; then
            echo '[!] Owned service exceeded graceful shutdown deadline' >&2
            kill -KILL "-$child" 2>/dev/null || kill -KILL "$child" || true
            break
        fi
        sleep 0.1 &
        wait $! || true
        continue
    fi
    if [ "$ended" = false ] && [ -r /run/ecd-gui-session/state ]; then
        generation= phase=
        read -r generation phase < /run/ecd-gui-session/state || true
        case "$generation" in *[!0-9a-f]*|'') phase=invalid;; esac
        if [ "${#generation}" -eq 32 ] && [ "$phase" = ended ]; then
            ended=true
            echo '[+] Intentional GUI end observed by service supervisor'
            # Only web services retain a bounded terminal-notification window.
            # The endpoint and orderly WS close let loaded clients cancel retries.
            deadline=$(( $(date +%s) + ${ECD_GUI_NOTIFY_GRACE:-0} ))
        fi
    fi
    if [ "$ended" = true ] && [ "$(date +%s)" -ge "$deadline" ]; then
        terminate
        continue
    fi
    sleep 0.2 &
    wait $! || true
done
status=0
wait "$child" || status=$?
if [ "$ended" = true ] || [ "$stopping" = true ]; then
    echo '[+] GUI session service stopped cleanly'
    exit 0
fi
exit "$status"
