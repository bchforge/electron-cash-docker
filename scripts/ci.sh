#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode=${1:-}
case "$mode" in
    -h|--help|help)
        printf '%s\n' \
            "Usage: ./scripts/ci.sh {fast|gate|sast|acceptance|platform-run <scope>}" \
            "  fast                         Lightweight automated regression checks" \
            "  gate                         Complete provider-independent validation" \
            "  platform-run linux-x11       Real Linux desktop/X11 smoke check" \
            "  platform-run mac-xquartz    Real macOS/XQuartz smoke check" \
            "  platform-run ledger-linux   Physical Ledger check on native Linux"
        ;;
    platform-run)
        shift
        exec python3 "${SCRIPT_DIR}/platform_runner.py" "$@"
        ;;
    *)
        exec python3 "${SCRIPT_DIR}/ci.py" "$@"
        ;;
esac
