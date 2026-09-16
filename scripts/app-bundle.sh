#!/bin/bash
# 为 macOS 组装 Easyss.app 应用包。
#
# 用法：bash scripts/app-bundle.sh <binary> <icns> <plist> [out-dir]
#   binary:  编译好的 Go 二进制文件路径（例如 bin/easyss）
#   icns:    .icns 图标文件路径（例如 icon/Easyss.icns）
#   plist:   Info.plist 文件路径（例如 cmd/easyss/Info.plist）
#   out-dir: 放置 Easyss.app 的目录（相对于仓库根目录），
#            默认为 bin，这样 `make easyss-mac-app` 会持续写入 bin/Easyss.app。
#            CI 传入 bin/darwin-<arch>，使两个 macOS 架构各自保留
#            自己的应用包，而不是互相覆盖。
#
# .icns 图标是预先生成的（参见 scripts/gen_icns.sh，在 macOS 上运行）
# 并已签入仓库，因此本脚本与平台无关。
# 输出：<out-dir>/Easyss.app/

set -euo pipefail

BINARY="$1"
ICNS="$2"
PLIST="$3"
OUT_DIR="${4:-bin}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

APP_DIR="${REPO_ROOT}/${OUT_DIR}/Easyss.app"

echo "Assembling ${APP_DIR}..."

rm -rf "${APP_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS"
mkdir -p "${APP_DIR}/Contents/Resources"

cp "${BINARY}" "${APP_DIR}/Contents/MacOS/easyss"
chmod +x "${APP_DIR}/Contents/MacOS/easyss"

cp "${ICNS}" "${APP_DIR}/Contents/Resources/Easyss.icns"

cp "${PLIST}" "${APP_DIR}/Contents/Info.plist"

echo "Done: ${APP_DIR}"
