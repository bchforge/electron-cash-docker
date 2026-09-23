#!/bin/bash

set -euo pipefail

SOURCE=${SOURCE:-/wallet}
BACKUP_NETWORK=${BACKUP_NETWORK:-mainnet}
EC_VERSION=${EC_VERSION:-4.4.6}
GPG_HOME=$(mktemp -d /tmp/ecd-gpg.XXXXXX)
trap 'rm -rf "${GPG_HOME}"' EXIT
chmod 700 "${GPG_HOME}"
export GNUPGHOME="${GPG_HOME}"

run_python() {
    /opt/electroncash-venv/bin/python /home/electroncash/backup_tool.py "$@"
}

decrypt_to_plaintext() {
    local archive=$1
    local prefix=$2
    local plain
    [ -f "${archive}" ] || { echo "[!] backup archive is missing" >&2; return 1; }
    plain=$(mktemp "/tmp/${prefix}.XXXXXX")
    chmod 600 "${plain}"
    if ! gpg --no-options --batch --yes --quiet --pinentry-mode loopback \
        --no-symkey-cache --passphrase-fd 3 --decrypt "${archive}" > "${plain}"; then
        rm -f "${plain}"
        echo "[!] backup decryption or integrity verification failed" >&2
        return 1
    fi
    printf '%s\n' "${plain}"
}

if [ "${1:-}" = "create" ]; then
    exec 3<&0
    if [ "${2:-}" = "--stdout" ] && [ "$#" -eq 2 ]; then
        set -o pipefail
        run_python create "${SOURCE}" \
            | gpg --no-options --batch --yes --quiet --pinentry-mode loopback \
                --no-symkey-cache --passphrase-fd 3 --symmetric --cipher-algo AES256 \
                --digest-algo SHA256 --s2k-digest-algo SHA256 --s2k-cipher-algo AES256 \
                --output -
        exit $?
    fi
    if [ "$#" -ne 2 ] || [[ "${2}" != /backups/* ]]; then
        echo "[!] create requires --stdout or an archive path under /backups" >&2
        exit 2
    fi
    archive=$2
    [ ! -e "${archive}" ] && [ ! -L "${archive}" ] || {
        echo "[!] backup already exists" >&2
        exit 1
    }
    archive_dir=$(dirname "${archive}")
    [ -d "${archive_dir}" ] || { echo "[!] backup directory is missing" >&2; exit 1; }
    temporary=$(mktemp "${archive}.tmp.XXXXXX")
    cleanup_archive() { rm -f "${temporary}"; }
    trap 'cleanup_archive; rm -rf "${GPG_HOME}"' EXIT
    set -o pipefail
    run_python create "${SOURCE}" \
        | gpg --no-options --batch --yes --quiet --pinentry-mode loopback \
            --no-symkey-cache --passphrase-fd 3 --symmetric --cipher-algo AES256 \
            --digest-algo SHA256 --s2k-digest-algo SHA256 --s2k-cipher-algo AES256 \
            --output "${temporary}"
    [ -s "${temporary}" ] || { echo "[!] backup output was empty" >&2; exit 1; }
    chmod 644 "${temporary}"
    if ! ln "${temporary}" "${archive}" 2>/dev/null; then
        if [ -e "${archive}" ] || [ -L "${archive}" ]; then
            echo "[!] backup already exists" >&2
            exit 1
        fi
        mv "${temporary}" "${archive}"
    else
        rm -f "${temporary}"
    fi
    exit 0
fi

if [ "${1:-}" = "verify" ]; then
    [ "$#" -eq 2 ] || { echo "[!] verify requires an archive path" >&2; exit 2; }
    exec 3<&0
    plain=$(decrypt_to_plaintext "$2" ecd-verify)
    trap 'rm -f "${plain}"; rm -rf "${GPG_HOME}"' EXIT
    run_python verify "${plain}"
    exit $?
fi

if [ "${1:-}" = "restore" ]; then
    [ "$#" -eq 2 ] || { echo "[!] restore requires an archive path and an empty target" >&2; exit 2; }
    exec 3<&0
    plain=$(decrypt_to_plaintext "$2" ecd-restore)
    trap 'rm -f "${plain}"; rm -rf "${GPG_HOME}"' EXIT
    run_python restore "${plain}" "${SOURCE}"
    exit $?
fi

if [ "${1:-}" = "replace" ]; then
    [ "$#" -eq 2 ] || { echo "[!] replace requires an archive path" >&2; exit 2; }
    exec 3<&0
    plain=$(decrypt_to_plaintext "$2" ecd-replace)
    trap 'rm -f "${plain}"; rm -rf "${GPG_HOME}"' EXIT
    run_python replace "${plain}" "${SOURCE}"
    exit $?
fi

if [ "${1:-}" = "snapshot" ]; then
    [ "$#" -eq 2 ] || { echo "[!] snapshot requires a destination" >&2; exit 2; }
    run_python snapshot "${SOURCE}" "$2"
    exit $?
fi

if [ "${1:-}" = "restore-snapshot" ]; then
    [ "$#" -eq 2 ] || { echo "[!] restore-snapshot requires a snapshot" >&2; exit 2; }
    run_python restore-snapshot "$2" "${SOURCE}"
    exit $?
fi

echo "usage: backup.sh create --stdout|/backups/file | verify ARCHIVE | restore ARCHIVE | replace ARCHIVE | snapshot TARGET | restore-snapshot SNAPSHOT" >&2
exit 2
