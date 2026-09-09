#!/bin/bash

set -euo pipefail

# Fetch and package only explicitly pinned plugin sources. The resulting ZIP is
# verified before it can be copied into the runtime image.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
MANIFEST="${PLUGIN_MANIFEST:-${PROJECT_ROOT}/plugins.json}"
OUTPUT_DIR="${PLUGIN_OUTPUT_DIR:-${SCRIPT_DIR}/zips}"

GENERATE=false
VERIFY_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --generate|--generate-hashes) GENERATE=true ;;
        --verify-only) VERIFY_ONLY=true ;;
        *) echo "[!] Unknown argument: ${arg}"; exit 1 ;;
    esac
done

if [ ! -f "${MANIFEST}" ]; then
    echo "[!] Plugin manifest not found: ${MANIFEST}"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

PLUGIN_DATA=$(python3 - "${MANIFEST}" <<'PY'
import json
import re
import sys

manifest_path = sys.argv[1]
with open(manifest_path, encoding="utf-8") as handle:
    document = json.load(handle)

plugins = document.get("plugins")
if not isinstance(plugins, list):
    raise SystemExit("[!] plugins must be a list")

hash_pattern = re.compile(r"^[0-9a-f]{64}$")
required = {
    "package_name", "source", "artifact", "version",
    "archive_root", "archive_sha256", "sha256", "enabled",
}
for plugin in plugins:
    missing = required - plugin.keys()
    if missing:
        raise SystemExit(
            f"[!] Plugin {plugin.get('package_name', '?')} missing: "
            + ", ".join(sorted(missing))
        )
    if not isinstance(plugin["enabled"], bool):
        raise SystemExit(f"[!] Plugin {plugin['package_name']} enabled must be boolean")
    if not plugin["source"].startswith("https://") or not plugin["artifact"].startswith("https://"):
        raise SystemExit(f"[!] Plugin {plugin['package_name']} sources must use HTTPS")
    for key in ("archive_sha256", "sha256"):
        if not hash_pattern.fullmatch(plugin[key]):
            raise SystemExit(f"[!] Plugin {plugin['package_name']} has invalid {key}")
    print("\t".join(str(plugin[key]) for key in (
        "package_name", "version", "source", "artifact",
        "archive_root", "archive_sha256", "sha256",
    )))
PY
)

if [ -z "${PLUGIN_DATA}" ]; then
    echo "[!] Plugin manifest contains no plugins"
    exit 1
fi

FAILED=false
while IFS=$'\t' read -r package_name version source artifact archive_root expected_archive_hash expected_zip_hash; do
    [ -n "${package_name}" ] || continue
    zip_name="${package_name}-${version}.zip"
    zip_path="${OUTPUT_DIR}/${zip_name}"

    echo ""
    echo "=============================================="
    echo "  Plugin: ${package_name} v${version}"
    echo "  Source: ${source}"
    echo "=============================================="

    if [ "${VERIFY_ONLY}" = "false" ]; then
        work_dir=$(mktemp -d)
        archive_path="${work_dir}/source.tar.gz"
        curl --fail --silent --show-error --location --retry 3 --proto '=https' \
            --tlsv1.2 "${artifact}" --output "${archive_path}"
        if ! echo "${expected_archive_hash}  ${archive_path}" | sha256sum --check --status; then
            echo "[!] SOURCE HASH MISMATCH for ${package_name}-${version}"
            rm -rf "${work_dir}"
            FAILED=true
            continue
        fi

        tar --extract --gzip --file "${archive_path}" --directory "${work_dir}"
        source_dir="${work_dir}/${archive_root}"
        if [ ! -d "${source_dir}/${package_name}" ] || [ ! -f "${source_dir}/manifest.json" ]; then
            echo "[!] Pinned source has an unexpected plugin layout"
            rm -rf "${work_dir}"
            FAILED=true
            continue
        fi

        python3 - "${source_dir}/manifest.json" "${package_name}" "${version}" <<'PY'
import json
import sys

manifest_path, expected_package, expected_version = sys.argv[1:]
with open(manifest_path, encoding="utf-8") as handle:
    metadata = json.load(handle)
if metadata.get("package_name") != expected_package:
    raise SystemExit("[!] Plugin metadata package_name does not match trusted manifest")
if str(metadata.get("version")) != expected_version:
    raise SystemExit("[!] Plugin metadata version does not match trusted manifest")
if "qt" not in metadata.get("available_for", []):
    raise SystemExit("[!] Plugin does not declare Electron Cash Qt compatibility")
PY

        rm -f "${zip_path}"
        SOURCE_DIR="${source_dir}" ZIP_PATH="${zip_path}" PACKAGE_NAME="${package_name}" \
            python3 <<'PY'
import os
import zipfile
from pathlib import Path

source_dir = Path(os.environ["SOURCE_DIR"])
zip_path = os.environ["ZIP_PATH"]
package_name = os.environ["PACKAGE_NAME"]
entries = [(Path("manifest.json"), source_dir / "manifest.json")]
entries.extend(
    (path.relative_to(source_dir), path)
    for path in sorted((source_dir / package_name).rglob("*"))
    if path.is_file() and path.suffix != ".pyc" and "__pycache__" not in path.parts
)

with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as archive:
    for relative_path, source_path in entries:
        info = zipfile.ZipInfo(str(relative_path), date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o644 << 16
        archive.writestr(info, source_path.read_bytes())
PY
        rm -rf "${work_dir}"
    fi

    if [ ! -f "${zip_path}" ]; then
        echo "[!] Verified plugin ZIP is missing: ${zip_path}"
        FAILED=true
        continue
    fi

    actual_zip_hash=$(sha256sum "${zip_path}" | cut -d' ' -f1)
    echo "[*] ZIP SHA-256: ${actual_zip_hash}"
    if [ "${GENERATE}" = "true" ]; then
        echo "[*] Generate mode: set sha256 to ${actual_zip_hash}"
        continue
    fi
    if [ "${actual_zip_hash}" != "${expected_zip_hash}" ]; then
        echo "[!] ZIP HASH MISMATCH for ${package_name}-${version}"
        echo "[!]   Expected: ${expected_zip_hash}"
        echo "[!]   Actual:   ${actual_zip_hash}"
        FAILED=true
        continue
    fi
    echo "[+] Plugin artifact verified"
done <<< "${PLUGIN_DATA}"

if [ "${FAILED}" = "true" ]; then
    echo "[!] Plugin build/verification FAILED"
    exit 1
fi

echo "[+] All trusted plugins built and verified"
