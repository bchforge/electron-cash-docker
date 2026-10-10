#!/bin/sh

set -eu

fail() { echo "[!] $*" >&2; exit 1; }

# A local image tag never selects or authenticates its compiled Caddy version.
CADDY_VERSION=${CADDY_VERSION-2.11.7}
CADDY_ARCHIVE_SHA256=${CADDY_ARCHIVE_SHA256-86e39de5fa0bc433a9cd574a00e7751059903401f3389c61f8937fd0ad0180f5}
sh /usr/local/bin/caddy-version-check "${CADDY_VERSION}" "${CADDY_ARCHIVE_SHA256}" || fail "invalid Caddy source selection"
[ "$(cat /etc/caddy/source-version)" = "${CADDY_VERSION}" ] && \
[ "$(cat /etc/caddy/source.sha256)" = "${CADDY_ARCHIVE_SHA256}" ] && \
[ "$(caddy version)" = "v${CADDY_VERSION}" ] || fail "Caddy image does not match configured source pin; rebuild Caddy before starting"

SITE_ADDRESS=${CADDY_SITE_ADDRESS:-localhost}
TLS_MODE=${CADDY_TLS_MODE:-auto}
ECD_MODE=${ECD_MODE:-novnc}
AUTH_UPSTREAM=${AUTH_SESSION_UPSTREAM:-auth-session:8080}
SITE_HOST=${SITE_ADDRESS#http://}
SITE_HOST=${SITE_HOST#https://}
CF_IPV4_FILE=/etc/caddy/cloudflare-ipv4.txt
CF_IPV6_FILE=/etc/caddy/cloudflare-ipv6.txt
BAN_STATE_DIR=/var/lib/caddy-bans
CADDYFILE=${BAN_STATE_DIR}/Caddyfile
BANNED_SNIPPET=${BAN_STATE_DIR}/banlist.caddy
TRUSTED_PROXY_FILE=${BAN_STATE_DIR}/trusted-proxies.txt
ADMIN_DIR=/run/caddy
ADMIN_SOCKET=${ADMIN_DIR}/admin.sock

[ "${ECD_MODE}" = novnc ] || fail "Caddy supports MODE=novnc only; do not expose headless Electron Cash through Caddy"
[ -n "${SITE_ADDRESS}" ] || fail "CADDY_SITE_ADDRESS is required"
case "${SITE_ADDRESS}" in
    *[!A-Za-z0-9:/._-]*) fail "CADDY_SITE_ADDRESS contains unsupported characters" ;;
    http://|https://) fail "CADDY_SITE_ADDRESS must include a host" ;;
esac
case "${TLS_MODE}" in
    auto|internal) ;;
    *) fail "CADDY_TLS_MODE must be auto or internal" ;;
esac
case "${SITE_HOST}" in
    localhost|127.0.0.1) LOCAL_MODE=true ;;
    *) LOCAL_MODE=false ;;
esac

read_cidrs() {
    file=$1
    [ -s "${file}" ] || fail "Cloudflare CIDR file is missing or empty: ${file}"
    result=
    while IFS= read -r cidr || [ -n "${cidr}" ]; do
        case "${cidr}" in
            "") fail "Cloudflare CIDR file contains an empty line: ${file}" ;;
            *[!A-Fa-f0-9:./]*) fail "Cloudflare CIDR file contains invalid characters: ${file}" ;;
        esac
        result="${result} ${cidr}"
    done < "${file}"
    [ -n "${result}" ] || fail "Cloudflare CIDR file has no ranges: ${file}"
    printf '%s' "${result# }"
}

if [ -n "${CADDY_TRUSTED_PROXIES:-}" ]; then
    case "${CADDY_TRUSTED_PROXIES}" in
        *[!A-Fa-f0-9:./\ ]*) fail "CADDY_TRUSTED_PROXIES contains unsupported characters" ;;
    esac
    TRUSTED_PROXY_CIDRS=${CADDY_TRUSTED_PROXIES}
else
    TRUSTED_PROXY_CIDRS="$(read_cidrs "${CF_IPV4_FILE}") $(read_cidrs "${CF_IPV6_FILE}")"
fi
mkdir -p "${BAN_STATE_DIR}" "${ADMIN_DIR}" /etc/caddy /var/log/caddy
printf '%s\n' ${TRUSTED_PROXY_CIDRS} > "${TRUSTED_PROXY_FILE}"
chmod 0640 "${TRUSTED_PROXY_FILE}"
if [ ! -f "${BANNED_SNIPPET}" ]; then
    printf '%s\n' '# No active Caddy client-IP bans.' > "${BANNED_SNIPPET}"
fi
rm -f "${ADMIN_SOCKET}"

{
    printf '%s\n' \
        '{' \
        '    admin unix//run/caddy/admin.sock' \
        '    servers {' \
        "        trusted_proxies static ${TRUSTED_PROXY_CIDRS}" \
        '        trusted_proxies_strict' \
        '        client_ip_headers CF-Connecting-IP X-Forwarded-For' \
        '    }'
    if [ "${LOCAL_MODE}" = true ]; then
        printf '%s\n' '    auto_https disable_redirects'
    fi
    printf '%s\n' \
        '}' \
        '' \
        '(ecd_handlers) {' \
        '    route {' \
        '        import /var/lib/caddy-bans/banlist.caddy' \
        '        @login_page path /' \
        '        handle @login_page {' \
        "            reverse_proxy ${AUTH_UPSTREAM} {" \
        '                header_up Host {host}' \
        '                header_up X-Forwarded-Proto {scheme}' \
        '            }' \
        '        }' \
        '        @public_asset path /favicon.svg' \
        '        handle @public_asset {' \
        "            reverse_proxy ${AUTH_UPSTREAM} {" \
        '                header_up Host {host}' \
        '                header_up X-Forwarded-Proto {scheme}' \
        '            }' \
        '        }' \
        '        @auth_endpoint path /auth/login /auth/logout /auth/gui-session' \
        '        handle @auth_endpoint {' \
        "            reverse_proxy ${AUTH_UPSTREAM} {" \
        '                header_up Host {host}' \
        '                header_up X-Forwarded-Proto {scheme}' \
        '            }' \
        '        }' \
        "        forward_auth ${AUTH_UPSTREAM} {" \
        '            uri /auth/check' \
        '            header_up Host {host}' \
        '            header_up X-Forwarded-Proto {scheme}' \
        '        }' \
        '        reverse_proxy electron-cash:6080 {' \
        '            header_up -Authorization' \
        '            header_up -Cookie' \
        '        }' \
        '    }' \
        '    log {' \
        '        output file /var/log/caddy/access.log {' \
        '            roll_size 10MiB' \
        '            roll_keep 5' \
        '            roll_keep_for 24h' \
        '        }' \
        '        format json' \
        '    }' \
        '}' \
        ''
    if [ "${LOCAL_MODE}" = true ]; then
        printf '%s\n' \
            ':80 {' \
            '    import ecd_handlers' \
            '}' \
            'https://localhost:443 {' \
            '    tls internal' \
            '    import ecd_handlers' \
            '}' \
            'https://127.0.0.1:443 {' \
            '    tls internal' \
            '    import ecd_handlers' \
            '}'
    else
        printf '%s\n' \
            "http://${SITE_HOST}:80 {" \
            '    redir https://'"${SITE_HOST}"'{uri} permanent' \
            '}'
        if [ "${TLS_MODE}" = internal ]; then
            printf '%s\n' \
                "https://${SITE_HOST}:443 {" \
                '    tls internal' \
                '    import ecd_handlers' \
                '}'
        else
            printf '%s\n' \
                "https://${SITE_HOST}:443 {" \
                '    import ecd_handlers' \
                '}'
        fi
    fi
} > "${CADDYFILE}"

caddy validate --config "${CADDYFILE}" || fail "generated Caddy configuration is invalid"
if [ "${LOCAL_MODE}" = true ]; then
    echo "[+] Starting session-authenticated Caddy noVNC edge for ${SITE_ADDRESS} (local dual HTTP/HTTPS)"
else
    echo "[+] Starting session-authenticated Caddy noVNC edge for ${SITE_ADDRESS} (public HTTPS with HTTP redirect)"
fi
exec caddy run --config "${CADDYFILE}" --adapter caddyfile
