# AGENTS.md — Easyss v3

## 项目概述

Easyss 是一款兼容 SOCKS5/HTTP 代理的安全上网工具，客户端+服务端架构。

## Go 环境

- 模块路径：`github.com/nange/easyss/v3`（根模块原地升级，不维护 v2/v3 双模块）
- Go 版本：`1.27.3+`（go.mod）

## 核心目录结构

```
rule/                               规则文件解析与匹配（IP/CIDR/域名/glob/regexp），客户端路由与服务端链式代理共用
cmd/easyss/                         客户端入口：参数解析、配置加载与子命令分发（main.go）
cmd/easyss/icon/                    托盘图标与更新徽章（//go:embed 运行时 PNG + badge.go）
cmd/easyss/internal/app/            客户端运行时：App/session/启动路径/托盘胶水/通知（启动路径与系统代理见 docs/platform.md）
cmd/easyss/internal/tray/           systray 控件：外壳、菜单、标题、更新状态机、UWP 豁免
cmd/easyss/internal/tunhelper/      TUN 提权 helper（unix fd 传递 / Windows 引擎）、spawn 与路由拆除复核
cmd/easyss/internal/sysproxy/       系统代理与 Linux 桌面会话环境
cmd/easyss/internal/logview/        查看日志（终端/快照）与桌面会话启动
cmd/easyss/internal/autostart/      开机自启
cmd/easyss/internal/singleton/      单实例锁
cmd/easyss/internal/selfupdatecmd/  selfupdate 子命令与产品变体
cmd/easyss-server/                  服务端入口，单文件 main.go
integration/                        客户端+服务端端到端测试（原 cmd/easyss/easyss_test.go）
runner/                             客户端启动与本地端点绑定（SOCKS5/HTTP/forward DNS :53）、服务端域名预解析
client/                             客户端核心：Client 结构体
client/assets/                      嵌入的 GeoIP 数据库、直连/屏蔽列表与 wintun DLL
client/config/                      客户端配置（JSON 解析、简化模式/旧版配置转换）
client/router/                      GeoIP + 域名列表路由引擎
client/dns/                         DNS 转发服务器（仅路由器透明代理 + TUN）+ freecache 双缓存（DNS 契约见 docs/architecture.md）
client/proxy/                       SOCKS5/HTTP 代理服务器 + StreamHandler
client/tun/                         TUN2socks 虚拟网卡 + ICMP 代理（teardown/脚本约束见 docs/platform.md）
client/tun/scripts/                 TUN 创建/关闭脚本（//go:embed，按 GOOS 自动选择）
server/                             服务端核心：Server 结构体（TLS/certmagic）
server/config/                      服务端配置类型
server/handler/                     TCP/UDP/ICMP 请求处理 + fallback 伪装页面
server/handler/assets/fallback/     fallback 模板/CSS/内容（//go:embed：template.html + themes.json + content.json）
server/nextproxy/                   上游 SOCKS5 代理（动态 IP/域名学习）
transport/                          传输层抽象：Transport/Stream 接口
transport/http2/                    HTTP/2 传输实现（uTLS Chrome 指纹，least-active 槽位调度，懒加载扩容；代/连接不变量见 docs/architecture.md）
protocol/                           应用帧协议：HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER 编解码
crypto/                             加密层：PBKDF2 KDF + HKDF key 派生 + 计数器 nonce AEAD（两阶段）
shaper/                             流量整形：分桶 padding + cover traffic 注入 + 批处理
relay/                              双向中继：Bidirectional(idleTimeout, src→dst, dst→src)
stats/                              全局原子计数器 + 快照（streams/bytes/RTT/DNS hits 等）
config/                             共享常量（默认端口、端点路径、buffer 大小等）
log/                                基于 slog 的日志，默认时区 Asia/Shanghai
util/                               工具函数（网络、文件、DNS、系统命令）
util/bytespool/                     字节缓冲池（2 的幂次分配器，最大 128KB）
docs/                               架构/配置不变量（architecture.md）、平台与 TUN 约束（platform.md）、README 截图（images/）
build/                              构建/打包资源与工具（darwin bundle/icns/plist、windows manifest/ico/syso、图标源图、证书示例）
pprof/                              可选 pprof HTTP 服务（127.0.0.1:6060）
version/                            构建版本信息（GitTag、BuildDate 等）
```

## 构建命令

### 本机开发（产物写在 `bin/` 根目录）

```bash
make easyss                # 客户端（Linux/macOS）
make easyss-windows        # 客户端（Windows）
make easyss-server
make easyss-server-windows
make easyss-headless       # 无托盘/Android
make easyss-android-aar    # 需要 JDK；gomobile/gobind 安装见 Makefile 注释
make icons                 # 重新生成 macOS 图标（sips/iconutil）
make syso                  # 重新生成 Windows 资源（rsrc）
make worktree-clean        # 清理 .agents/worktrees 下的 agent 工作树（不删分支）
```

### CI / 发布（产物写在 `bin/<os>-<arch>/`）

```bash
make build   # 6 个平台：linux/windows/darwin × amd64/arm64
make pack    # build + 14 个 zip（bin/*.zip）
make dist    # pack + Android AAR（release/nightly 使用）
make verify  # lint + test-race
make clean   # 只清 CI 产物；bin/ 下的本机二进制与配置不动

# 单平台：make build-<os>-<arch>，产物在 bin/<os>-<arch>/
# 如 make build-darwin-arm64、make build-linux-amd64
```

zip 资产名与 zip 内的二进制名是客户端自更新（`selfupdate/product.go`）与
`docker/Dockerfile` 的对外契约，不要重命名。

> `.PHONY` 只是声明行，不要把 `make .PHONY` 当目标——它会把 format/lint/test/全部构建跑一遍。

## 测试与 lint

```bash
go test -v ./...                        # 全部
go test -v ./crypto/...                 # 单包
go test -v ./server/ -run TestCertmagic # 单测试
make lint                               # golangci-lint + go fix 检查
```

## 构建标签

- `headless`：编译 `cmd/easyss/internal/app/run_headless.go` 而非 `run.go` + 托盘胶水
- `cmd/easyss/internal/app/run.go`、`tray.go` 与 `cmd/easyss/internal/tray/*.go` 头部是 `//go:build !headless`
- 系统代理与三条启动路径的约束见 [docs/platform.md](docs/platform.md)。

## 配置相关

- 显示完整配置示例：`./easyss -show-config-example`
- 配置加载、字段语义与归一化不变量以 [docs/architecture.md](docs/architecture.md) 的「配置相关」一节为准。

## 深入阅读

`AGENTS.md` 只保留目录、构建/测试命令与代码约定；改动前按子系统读对应文档，代码契约变化时同步更新（冲突以代码为准）：

- [docs/architecture.md](docs/architecture.md)：架构要点（按子系统分节：传输、协议、加密、fallback、DNS、规则）与配置不变量。
- [docs/platform.md](docs/platform.md)：Windows 打包、启动路径/系统代理、TUN 脚本参数与 teardown 生命周期。

## 版本信息注入

Makefile 用 `-ldflags -X` 只注入 `version.Name`、`GitTag`、`BuildDate`；`GitCommit`/`GitCommitDate`/`GitTreeState` 由 `runtime/debug.ReadBuildInfo()` 收集，`GoVersion`/`Platform` 取自 `runtime`，均在 `version.init()` 中补齐。

## 规范约定

- 测试注入约定：**不新增包级可变函数钩子**（`var x = func...`），一律用构造器参数、结构体字段或接口注入；测试只改自己构造的实例（`client.sysDeps`、`tun.platform`、`handler.outboundDeps`、`runner.options`、`appDeps`、`tunhelper` 的 `ops`（包内测试）、`sysproxy.State`、`dns.systemServers` 等）。生产默认值由构造器或 `defaultXxx()` 填入，**零值不回落**：新增依赖字段后忘了填是编译期就能看见的 nil 调用，而不是悄悄走生产实现。唯一例外是 `client.sysDeps` 的 nil 字段——它的 `dialBound` 默认值必须引用所属 `Client`，没法在结构体字面量里填。`t.Parallel` 已按包启用；仍需串行的只有共享进程级状态的测试（fd 号、全局 logger、`t.Setenv`、真实端口），它们在文件顶部或测试函数上注明原因
- 导入别名约定：根 `config` 包（默认值、`Timeouts`、`SimpleConfig`）按包名裸导入，不写 `sharedconfig` 之类的别名；同一文件还要引入 `client/config` 或 `server/config` 时，把别名给后者（`clientconfig` / `serverconfig`），让 `config.` 在整仓恒定指向根包。同一个包内 `config.` 只能指向一个包，不得按文件各取所需
- 注释约定：代码注释只写"读代码看不出来、写错会静默出错"的两类事实——顺序/锁/生命周期约束，以及外部系统行为或跨包契约。不写代码演进史（"过去…现在…"、"取代了某某"），不写枚举式清单（"只有这五个方法会写这个字段"）——这类表述一旦过时就成了错误文档；设计取舍与历史写在 commit message 或本文件。单个注释块不超过 3 行，函数名已经说清楚的不要再加 godoc
- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录
- **git worktree**：仅当当前处于 `master` 分支时，代码改动才先建 worktree 再改，目录固定为 `.agents/worktrees/<name>`（`<name>` 可用 `type/name` 分层），从当前 HEAD 或用户指定的 base 新建分支；已经在功能分支或用户指定分支/工作树上时直接改。该目录不提交，清理用 `make worktree-clean`（只删 `.agents/worktrees/` 下的工作树，不删分支）。
- 在用户没有明确要求提交代码前，都不提交代码
- 提交代码前，先执行`make lint`，检查代码风格，存在问题则需要先修复再提交代码
- **review PR**：目标是简洁高效——先确认代码是否已在本地（`git worktree list`、`.agents/worktrees/`、`git branch -r`、`git log --all` 里的 head 提交），命中就直接在该工作树/分支评审（需要最新提交只 `git fetch`），本地确实没有才 clone 或下载补丁；评审从 PR 描述与改动范围入手，只输出影响正确性、跨包契约或明显维护成本的问题，结论先行并给出文件/行号与依据，不逐段复述 diff、不凑格式性建议
- 当用户要求提交PR时，需要在单独的分支提交代码并推送，PR标题采用英文，PR描述使用中文
