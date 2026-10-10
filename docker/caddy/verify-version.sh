#!/bin/sh
# Reviewed operational floor: GHSA-6365-7ppr-5r92 is fixed in 2.11.5;
# 2.11.6 adds auth hardening and 2.11.7 fixes its proxy/stream regressions.
set -eu
version=${1-}
digest=${2-}
case "$version" in *[!0-9.]*) echo '[!] invalid CADDY_VERSION characters' >&2; exit 1 ;; esac
case "$digest" in *[!0-9a-f]*) echo '[!] invalid CADDY_ARCHIVE_SHA256 characters' >&2; exit 1 ;; esac
if ! printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'; then
    echo '[!] CADDY_VERSION requires a precise stable major.minor.patch' >&2
    exit 1
fi
if ! printf '%s\n' "$digest" | grep -Eq '^[0-9a-f]{64}$'; then
    echo '[!] CADDY_ARCHIVE_SHA256 requires a reviewed lowercase SHA-256' >&2
    exit 1
fi
# Reject excessively large fields before POSIX integer comparisons.
old_ifs=$IFS
IFS=.
set -- $version
IFS=$old_ifs
for component do
    [ "${#component}" -le 6 ] || { echo '[!] Caddy version field too large' >&2; exit 1; }
done
if [ "$1" -lt 2 ] || { [ "$1" -eq 2 ] && [ "$2" -lt 11 ]; } ||
   { [ "$1" -eq 2 ] && [ "$2" -eq 11 ] && [ "$3" -lt 7 ]; }; then
    echo '[!] Caddy must meet the reviewed 2.11.7 security/compatibility floor (GHSA-6365-7ppr-5r92)' >&2
    exit 1
fi
