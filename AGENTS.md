# AGENTS.md — Easyss v3

## 项目概述

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，客户端+服务端架构。

## Go 环境

- 模块路径：`github.com/nange/easyss/v3`（根模块原地升级，不维护 v2/v3 双模块）
- Go 版本：`1.26.3+`（go.mod）

## 核心目录结构

```
cmd/easyss/         客户端入口，含系统托盘(systray) UI，Windows/Mac 需要 CGO
cmd/easyss-server/  服务端入口，单文件 main.go
client/             客户端核心：Client 结构体
client/config/      客户端配置（JSON 解析、v2→v3 迁移）
client/router/      GeoIP + 域名列表路由引擎
client/dns/         DNS 转发服务器 + freecache 双缓存
client/proxy/       SOCKS5/HTTP 代理服务器 + StreamHandler
client/tun/         TUN2socks 虚拟网卡 + ICMP 代理
server/             服务端核心：Server 结构体（TLS/certmagic）
server/config/      服务端配置类型
server/handler/     TCP/UDP/ICMP 请求处理 + fallback 伪装页面
server/nextproxy/   上游 SOCKS5 代理（动态 IP/域名学习）
transport/          传输层抽象：Transport/Stream 接口
	transport/http2/    HTTP/2 传输实现（uTLS Chrome 指纹，least-active 槽位调度，懒加载扩容）
protocol/           应用帧协议：HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER 编解码
crypto/             加密层：PBKDF2 KDF + HKDF key 派生 + 计数器 nonce AEAD（两阶段）
shaper/             流量整形：分桶 padding + cover traffic 注入 + 批处理
relay/              双向中继：Bidirectional(idleTimeout, src→dst, dst→src)
stats/              全局原子计数器 + 快照（streams/bytes/RTT/DNS hits 等）
config/             共享常量（默认端口、端点路径、buffer 大小等）
log/                基于 slog 的日志，默认时区 Asia/Shanghai
util/               工具函数（网络、文件、DNS、系统命令）
util/bytespool/     字节缓冲池（2 的幂次分配器，最大 128KB）
assets/             嵌入的 GeoIP 数据库 + 直连/屏蔽域名列表
scripts/            各平台 TUN 设备脚本（//go:embed，按 GOOS 自动选择）
pprof/              可选 pprof HTTP 服务（127.0.0.1:6060）
icon/               平台特定托盘图标（darwin/linux/windows）
version/            构建版本信息（GitTag、BuildDate 等）
```

## 构建命令

```bash
# 客户端 (Linux/Mac)
make easyss

# 客户端 (Windows) — 需要 CGO_ENABLED=1，systray 依赖 CGO
make easyss-windows

# 服务端
make easyss-server

# 服务端 (Windows)
make easyss-server-windows

# Android AAR — 需要 gomobile 和 Android SDK
make easyss-android-aar

# 无系统托盘版本 (headless/Android)
make easyss-without-tray
```

### 交叉编译示例

```bash
# Linux ARM64 headless 客户端
GOOS=linux GOARCH=arm64 make easyss-without-tray

# Linux ARM64 服务端
GOOS=linux GOARCH=arm64 make easyss-server

# macOS ARM64 客户端
GOOS=darwin GOARCH=arm64 make easyss

# macOS ARM64 服务端
GOOS=darwin GOARCH=arm64 make easyss-server

# macOS Intel 客户端
GOOS=darwin GOARCH=amd64 make easyss

# macOS Intel 服务端
GOOS=darwin GOARCH=amd64 make easyss-server
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

1. **传输层**：基于 Go 1.26 标准库 HTTP/2（不依赖 `golang.org/x/net/http2`），初始 1 个 `http.Transport`（`MaxConnsPerHost=1`），按需懒加载扩容（活跃流达到 `stream_threshold` 阈值且仍小于 `conn_count_max` 上限时新建连接），通过 least-active 策略调度；TLS 握手使用 uTLS Chrome 指纹伪装；服务端和客户端 HTTP/2 参数（帧大小、窗口大小、HEADER TABLE SIZE）分别配置以增强伪装效果
2. **应用帧协议**：HTTP/2 stream 内封装 app 帧（HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER），`cipher_len:3 + ciphertext` 作为 CryptoRecord 边界；`protocol.ReadFrame/WriteFrame` 处理帧级别的编解码
3. **两阶段加密**：① Bootstrap 阶段：AES-256-GCM 加密初始握手帧（含目标地址和方法协商）；② Session 阶段：协商后的 AEAD（AES-256-GCM 或 ChaCha20-Poly1305），HKDF+salt 派生 C2S/S2C 方向独立密钥，每方向独立计数器 nonce
4. **回落对抗**：服务端首个 CryptoRecord 解密/验证失败时，回落成正常 HTML 首页（伪装为普通网站）；一旦发送 octet-stream 响应头则只能 close/RST stream；fallback 支持 5 种视觉主题 ×5 类内容页面，按 URL hash 确定性生成
5. **端点**：`POST /v3/tcp`、`POST /v3/udp`、`POST /v3/icmp`（强制 HTTP/2），其余路径返回 fallback HTML（允许 HTTP/1.1）
6. **服务端**：需要 sudo 运行（443 端口 + ICMP）；TLS 证书通过 certmagic 自动管理（Let's Encrypt ACME）或手动指定证书文件
7. **SSRF 防护**：服务端验证 HANDSHAKE 中的 target 地址，拒绝 LAN/私有 IP 目标，防止被用作跳板攻击内网
8. **流量整形**：`shaper` 包将帧分批打包为 CryptoRecord，填充至固定大小档位（128/512/1500 字节），支持按预算比例注入 cover traffic（随机 COVER 帧），批处理窗口默认 3ms
9. **双向中继**：`relay.Bidirectional` 在 client↔server 间拷贝数据，共享空闲计时器，连接关闭时回调 exactly once；支持 stall 检测和流量统计
10. **统计与监控**：`stats` 包维护全局原子计数器（streams、bytes、RTT、DNS 缓存命中/未命中、fallback 页面等）；通过 HTTP 代理端口的 `/stats` 端点暴露 JSON 快照；`StreamMeter` 提供 per-stream 吞吐量监控
11. **NextProxy 动态学习**：`server/nextproxy` 从 DNS 响应中自动提取 CNAME 目标域名和解析 IP，动态加入代理列表，无需预配置完整域名
12. **v2→v3 配置迁移**：`client/config/migrate.go` 自动检测 v2 格式配置文件并通过 `MigrateV2Config()` 转换为 v3 格式，迁移后备份原文件为 `.bak`

## 版本信息注入

Makefile 通过 `-ldflags` 向 `version/` 包注入以下变量，其余变量由 `runtime/debug.ReadBuildInfo()` 和 `runtime` 在 `init()` 中自动填充：

- `version.Name` → `"Easyss"`
- `version.GitTag` → `git describe --tags`
- `version.BuildDate` → 构建时间
- `version.GitCommit` → 完整 commit hash
- `version.GitTreeState` → `"clean"` 或 `"dirty"`
- `version.Platform` → `runtime.GOOS`/`runtime.GOARCH`
- `version.GoVersion` → `runtime.Version()`

## Windows 构建注意事项

- 客户端需要 CGO（`CGO_ENABLED=1`），依赖系统托盘库 `getlantern/systray`；服务端禁用 CGO
- 客户端产物连 `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`

## 其他注意事项

- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录
- 提交代码前，先执行`make lint`，检查代码风格，存在问题则需要先修复再提交代码
