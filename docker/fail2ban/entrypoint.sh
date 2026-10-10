#!/bin/bash

set -euo pipefail

integer() { [[ "$1" =~ ^[0-9]+$ ]]; }
MAXRETRY=${FAIL2BAN_MAXRETRY:-5}
FINDTIME=${FAIL2BAN_FINDTIME:-600}
BANTIME=${FAIL2BAN_BANTIME:-3600}
IGNOREIP=${FAIL2BAN_IGNOREIP:-127.0.0.0/8 ::1}
EDGE_BIND=${CADDY_EDGE_BIND:-127.0.0.1}
integer "${MAXRETRY}" && [ "${MAXRETRY}" -ge 1 ] && [ "${MAXRETRY}" -le 100 ] || { echo "[!] invalid FAIL2BAN_MAXRETRY" >&2; exit 1; }
integer "${FINDTIME}" && [ "${FINDTIME}" -ge 1 ] && [ "${FINDTIME}" -le 86400 ] || { echo "[!] invalid FAIL2BAN_FINDTIME" >&2; exit 1; }
integer "${BANTIME}" && [ "${BANTIME}" -ge 1 ] && [ "${BANTIME}" -le 604800 ] || { echo "[!] invalid FAIL2BAN_BANTIME" >&2; exit 1; }
case "${EDGE_BIND}" in
    127.0.0.1|::1) echo "[!] loopback-only Caddy edge: public per-client packet enforcement is not claimed" >&2 ;;
    0.0.0.0|::) ;;
    *) echo "[!] unsupported CADDY_EDGE_BIND for fail2ban: ${EDGE_BIND}" >&2; exit 1 ;;
esac

python3 - "${IGNOREIP}" <<'PY'
import ipaddress
import sys
for item in sys.argv[1].split():
    try:
        ipaddress.ip_network(item, strict=False)
    except ValueError as error:
        raise SystemExit(f"invalid FAIL2BAN_IGNOREIP entry: {item}") from error
PY

mkdir -p /var/lib/fail2ban
touch /var/lib/fail2ban/access.log
cat > /etc/fail2ban/jail.d/ecd.local <<EOF
[DEFAULT]
backend = auto
ignoreip = ${IGNOREIP}
bantime = ${BANTIME}
findtime = ${FINDTIME}
maxretry = ${MAXRETRY}
action = caddy-ban

[sshd]
enabled = false

[caddy-basicauth]
enabled = true
filter = caddy-basicauth
logpath = /var/lib/fail2ban/access.log
maxretry = ${MAXRETRY}
findtime = ${FINDTIME}
bantime = ${BANTIME}
EOF

/usr/local/bin/caddy-log-adapter &
ADAPTER_PID=$!
cleanup() {
    kill "${ADAPTER_PID}" 2>/dev/null || true
    wait "${ADAPTER_PID}" 2>/dev/null || true
}
trap cleanup EXIT

for _ in {1..120}; do
    if ! kill -0 "${ADAPTER_PID}" 2>/dev/null; then
        echo "[!] caddy-log-adapter exited before protection became ready" >&2
        wait "${ADAPTER_PID}" || true
        exit 1
    fi
    if /usr/local/bin/caddy-ban admin-check >/dev/null 2>&1; then
        break
    fi
    sleep 0.25
done
/usr/local/bin/caddy-ban admin-check >/dev/null 2>&1 || {
    echo "[!] Caddy admin socket did not become available" >&2
    exit 1
}
/usr/local/bin/caddy-ban reconcile

fail2ban-server -f --logtarget stdout &
F2B_PID=$!
for _ in {1..20}; do
    if ! kill -0 "${ADAPTER_PID}" 2>/dev/null; then
        echo "[!] caddy-log-adapter exited; refusing to run fail2ban without log protection" >&2
        kill "${F2B_PID}" 2>/dev/null || true
        wait "${F2B_PID}" || true
        exit 1
    fi
    if fail2ban-client status caddy-basicauth >/dev/null 2>&1; then
        echo "[+] fail2ban active with namespace-local packet and Caddy enforcement"
        while kill -0 "${F2B_PID}" 2>/dev/null; do
            if ! kill -0 "${ADAPTER_PID}" 2>/dev/null; then
                echo "[!] caddy-log-adapter exited; stopping fail2ban fail-closed" >&2
                kill "${F2B_PID}" 2>/dev/null || true
                wait "${F2B_PID}" || true
                exit 1
            fi
            sleep 1
        done
        wait "${F2B_PID}"
        exit $?
    fi
    if ! kill -0 "${F2B_PID}" 2>/dev/null; then
        echo "[!] fail2ban exited before its jail became active" >&2
        wait "${F2B_PID}" || true
        exit 1
    fi
    sleep 0.25
done
echo "[!] fail2ban jail did not become active" >&2
kill "${F2B_PID}" 2>/dev/null || true
wait "${F2B_PID}" || true
exit 1
