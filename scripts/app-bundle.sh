#!/bin/bash
# Assemble Easyss.app bundle for macOS.
#
# Usage: bash scripts/app-bundle.sh <binary> <icns> <plist>
#   binary: path to the compiled Go binary (e.g., bin/easyss)
#   icns:   path to the .icns icon (e.g., icon/Easyss.icns)
#   plist:  path to Info.plist (e.g., cmd/easyss/Info.plist)
#
# The .icns icon is pre-generated (see scripts/gen_icns.sh, run on macOS)
# and checked into the repo, so this script is platform-independent.
# Output: bin/Easyss.app/

set -euo pipefail

BINARY="$1"
ICNS="$2"
PLIST="$3"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APP_DIR="${REPO_ROOT}/bin/Easyss.app"

echo "Assembling ${APP_DIR}..."

rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

cp "${BINARY}" "${APP_DIR}/Contents/MacOS/easyss"
chmod +x "${APP_DIR}/Contents/MacOS/easyss"

cp "${ICNS}" "${APP_DIR}/Contents/Resources/Easyss.icns"

cp "${PLIST}" "${APP_DIR}/Contents/Info.plist"

echo "Done: ${APP_DIR}"
