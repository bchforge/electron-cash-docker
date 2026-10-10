#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
mode=${1:-}
case "$mode" in
    mac-apple-silicon)
        shift
        exec python3 "${SCRIPT_DIR}/../tests/test_mac_apple_silicon.py" "$@"
        ;;
    ledger-virtual)
        shift
        exec python3 "${SCRIPT_DIR}/../tests/test_ledger_virtual.py" "$@"
        ;;
    linux-x11)
        shift
        exec python3 "${SCRIPT_DIR}/../tests/test_linux_x11.py" "$@"
        ;;
    -h|--help|help)
        printf '%s\n' \
            "Usage: ./scripts/ci.sh {fast|gate|sast|acceptance|linux-x11|mac-apple-silicon|ledger-virtual|platform-run <scope>}" \
            "  mac-apple-silicon            Unattended real Apple Silicon / XQuartz validation" \
            "  ledger-virtual               Speculos / real Ledger plugin BCH regression" \
            "  linux-x11                    Automated local native-X11 platform validation" \
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
