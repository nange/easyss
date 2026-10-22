#!/usr/bin/env bash
# 重新生成 cmd/easyss 下的 Windows 资源：.syso 必须与 main 包同目录。
# 需要 rsrc：go install github.com/akavel/rsrc@latest
# 用法：bash build/windows/gen_syso.sh

set -euo pipefail

if ! command -v rsrc >/dev/null 2>&1; then
	echo "rsrc not found: go install github.com/akavel/rsrc@latest" >&2
	exit 1
fi

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BUILD_DIR="${REPO_ROOT}/build/windows"
OUT_DIR="${REPO_ROOT}/cmd/easyss"

for arch in amd64 arm64; do
	rsrc -arch "${arch}" \
		-manifest "${BUILD_DIR}/manifest.xml" \
		-ico "${BUILD_DIR}/icon_256_256.ico" \
		-o "${OUT_DIR}/easyss_windows_${arch}.syso"
done
