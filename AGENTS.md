# AGENTS.md — Easyss v3

## 项目概述

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，客户端+服务端架构。当前处于 **v2→v3 重构**阶段，v3 详细设计文档：`v3_detailed_design.md`。

## Go 环境

- 模块路径：`github.com/nange/easyss/v3`（根模块原地升级，不维护 v2/v3 双模块）
- Go 版本：`1.26.3+`（go.mod）

## 核心目录结构

```
cmd/easyss/         客户端入口，含系统托盘(systray) UI，Windows/Mac 需要 CGO
cmd/easyss-server/  服务端入口，单文件 main.go
client/             客户端核心：Client 结构体 + config/router/dns/proxy/tun 子包
server/             服务端核心：Server 结构体 + config/handler/nextproxy 子包
transport/          传输层抽象：Transport/Stream 接口 + HTTP/2 客户端实现
protocol/           应用帧协议：HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING 编解码
crypto/             加密层：PBKDF2 KDF + HKDF key 派生 + 计数器 nonce AEAD
shaper/             流量整形：分桶 padding + 5ms 批处理
config/             共享常量（默认端口、端点路径等）
log/                基于 slog 的日志，默认时区 Asia/Shanghai
util/               工具函数（网络、文件、随机数、bytes pool）
```

## 构建命令

```bash
# 客户端 (Linux/Mac)
make easyss

# 客户端 (Windows) — 需要 CGO_ENABLED=1，systray 依赖 CGO
make easyss-windows

# 服务端
make easyss-server

# Android (arm64) — 需要设置 ANDROID_NDK_HOME 且使用 without_tray tag
make easyss-android-arm64

# 无系统托盘版本 (headless/Android)
make easyss-without-tray
```

## 运行单个测试 / lint

```bash
# 测试所有包
go test -v ./...

# 测试单个包
go test -v ./crypto/...

# 测试单个文件（包内所有测试）
go test -v ./server/ -run TestCertmagic

# lint（跳过 _test.go 文件）
make lint   # 等价: go tool golangci-lint run --timeout 10m --verbose
```

## 构建标签 (Build Tags)

- `without_tray`：用于 headless/Android 构建，编译 `cmd/easyss/start_without_tray.go` 而非 `start.go`+`tray.go`
- 注意 `cmd/easyss/start.go` 和 `tray.go` 头部有 `//go:build !without_tray`

## 配置相关

- 默认配置文件名为 `config.json`，位于二进制同目录
- v2 配置自动迁移到 v3：`client/config/migrate.go` 中的 `MigrateV2Config()` 处理转换
- v3 客户端配置入口：`client/config/config.go` 中的 `ClientConfig` 结构体
- v3 服务端配置入口：`server/config/config.go` 中的 `FileConfig`/`ServerConfig`
- 显示完整配置示例：`./easyss -show-config-example`

## 关键架构要点

1. **传输层**：基于 Go 1.26 标准库 HTTP/2（不依赖 `golang.org/x/net/http2`），维护 8-16 个独立 `http.Transport`（每个 `MaxConnsPerHost=1`），通过 least-active 策略调度
2. **应用帧协议**：HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING），`cipher_len:3 + ciphertext` 作为 CryptoRecord 边界
3. **加密**：启动时一次性 PBKDF2 派生 master_key，每 stream 用 HKDF+salt 派生方向密钥；每方向独立计数器 nonce（不再每次 crypto/rand）
4. **回落对抗**：服务端首个 CryptoRecord 解密/验证失败时，回落成正常 HTML 首页（伪装为普通网站）；一旦发送 octet-stream 响应头则只能 close/RST stream
5. **端点**：`POST /v3/tcp`、`POST /v3/udp`、`POST /v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）
6. **服务端**：需要 sudo 运行（443 端口 + ICMP）；TLS 证书通过 certmagic 自动管理

## 版本信息注入

Makefile 通过 `-ldflags` 向 `version/` 包注入以下变量：

- `version.Name` → `"Easyss"`
- `version.GitTag` → `git describe --tags`
- `version.BuildDate` → 构建时间

## Windows 构建注意事项

- 需要 CGO（`CGO_ENABLED=1`），依赖系统托盘库 `getlantern/systray`
- 产物连 `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`

## 其他注意事项

- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录

## 待清理（v3 重构进行中）

v3 设计文档附件 D 列出了完整的删除/迁移清单。核心待删除：

- `README.md`文档内容更新
