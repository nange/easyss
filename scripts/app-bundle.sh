#!/bin/bash
# Assemble Easyss.app bundle for macOS.
#
# Usage: bash scripts/app-bundle.sh <binary> <png_icon> <plist>
#   binary:   path to the compiled Go binary (e.g., bin/easyss)
#   png_icon: path to the 1024x1024 PNG icon (e.g., icon/icon_1024_1024.png)
#   plist:    path to Info.plist (e.g., cmd/easyss/Info.plist)
#
# The .icns icon is generated on-the-fly from the PNG using sips + iconutil
# (macOS built-in tools). Output: bin/Easyss.app/

set -euo pipefail

BINARY="$1"
PNG_ICON="$2"
PLIST="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APP_DIR="${REPO_ROOT}/bin/Easyss.app"
ICNS_DIR="${REPO_ROOT}/bin/Easyss.iconset"
ICNS_FILE="${REPO_ROOT}/bin/Easyss.icns"

echo "Assembling ${APP_DIR}..."

# Generate .icns from PNG (macOS built-in tools).
if [ -f "${PNG_ICON}" ]; then
    echo "Generating ${ICNS_FILE} from ${PNG_ICON}..."
    rm -rf "${ICNS_DIR}"
    mkdir -p "${ICNS_DIR}"

    sips -z 16 16     "${PNG_ICON}" --out "${ICNS_DIR}/icon_16x16.png"
    sips -z 32 32     "${PNG_ICON}" --out "${ICNS_DIR}/icon_16x16@2x.png"
    sips -z 32 32     "${PNG_ICON}" --out "${ICNS_DIR}/icon_32x32.png"
    sips -z 64 64     "${PNG_ICON}" --out "${ICNS_DIR}/icon_32x32@2x.png"
    sips -z 128 128   "${PNG_ICON}" --out "${ICNS_DIR}/icon_128x128.png"
    sips -z 256 256   "${PNG_ICON}" --out "${ICNS_DIR}/icon_128x128@2x.png"
    sips -z 256 256   "${PNG_ICON}" --out "${ICNS_DIR}/icon_256x256.png"
    sips -z 512 512   "${PNG_ICON}" --out "${ICNS_DIR}/icon_256x256@2x.png"
    sips -z 512 512   "${PNG_ICON}" --out "${ICNS_DIR}/icon_512x512.png"
    sips -z 1024 1024 "${PNG_ICON}" --out "${ICNS_DIR}/icon_512x512@2x.png"

    iconutil -c icns "${ICNS_DIR}" -o "${ICNS_FILE}"
    rm -rf "${ICNS_DIR}"
fi

rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

cp "${BINARY}" "${APP_DIR}/Contents/MacOS/easyss"
chmod +x "${APP_DIR}/Contents/MacOS/easyss"

if [ -f "${ICNS_FILE}" ]; then
    cp "${ICNS_FILE}" "${APP_DIR}/Contents/Resources/Easyss.icns"
    rm -f "${ICNS_FILE}"
fi

cp "${PLIST}" "${APP_DIR}/Contents/Info.plist"

echo "Done: ${APP_DIR}"
