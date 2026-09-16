#!/bin/bash
# 从 1024x1024 的 PNG 源图生成 Easyss.icns。
# 需要装有 sips 和 iconutil 的 macOS。
#
# 用法：bash scripts/gen_icns.sh <source_1024x1024.png>
#
# 生成的 Easyss.icns 会放在 icon/ 目录下。
# 仅当图标设计变更时才需要运行本脚本。

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC_PNG="$1"
ICONSET="${REPO_ROOT}/icon/Easyss.iconset"
OUT_ICNS="${REPO_ROOT}/icon/Easyss.icns"

echo "Generating ${ICONSET} from ${SRC_PNG}..."

mkdir -p "${ICONSET}"

sips -z 16 16     "${SRC_PNG}" --out "${ICONSET}/icon_16x16.png"
sips -z 32 32     "${SRC_PNG}" --out "${ICONSET}/icon_16x16@2x.png"
sips -z 32 32     "${SRC_PNG}" --out "${ICONSET}/icon_32x32.png"
sips -z 64 64     "${SRC_PNG}" --out "${ICONSET}/icon_32x32@2x.png"
sips -z 128 128   "${SRC_PNG}" --out "${ICONSET}/icon_128x128.png"
sips -z 256 256   "${SRC_PNG}" --out "${ICONSET}/icon_128x128@2x.png"
sips -z 256 256   "${SRC_PNG}" --out "${ICONSET}/icon_256x256.png"
sips -z 512 512   "${SRC_PNG}" --out "${ICONSET}/icon_256x256@2x.png"
sips -z 512 512   "${SRC_PNG}" --out "${ICONSET}/icon_512x512.png"
sips -z 1024 1024 "${SRC_PNG}" --out "${ICONSET}/icon_512x512@2x.png"

iconutil -c icns "${ICONSET}" -o "${OUT_ICNS}"

rm -rf "${ICONSET}"

echo "Done: ${OUT_ICNS}"
