# build/

只放构建、打包用的资源与脚本；运行期 `//go:embed` 的托盘图标仍在 `cmd/easyss/icon/`。

| 路径 | 内容 | 入口 |
|---|---|---|
| `darwin/` | `Info.plist`、`Easyss.icns`、`app-bundle.sh` | `make easyss-mac-app`、`make build-darwin-*` |
| `windows/` | `manifest.xml`、`icon_256_256.ico`、`gen_syso.sh` | `make syso`（需要 `rsrc`） |
| `icon/` | 设计源图、`gen_icns.sh` | `make icons`（需要 macOS 的 `sips`/`iconutil`） |
| `certs/` | cfssl 自签证书示例 | `cd build/certs && bash example.sh` |

`gen_syso.sh` 会把 `.syso` 写回 `cmd/easyss/`，因为 Go 只链接 main 包同目录的资源文件。
