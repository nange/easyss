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
cmd/easyss/icon/                    客户端托盘图标与打包图标（运行时 embed PNG/ICO、Easyss.icns、设计源图）
cmd/easyss/internal/app/            客户端运行时：App/session/启动路径/托盘胶水/通知（nange/systray 分支，纯 Go 零 CGO）
cmd/easyss/internal/tray/           systray 控件：外壳、菜单、标题、更新状态机、UWP 豁免
cmd/easyss/internal/tunhelper/      TUN 提权 helper、fd 传递、spawn 与路由拆除复核
cmd/easyss/internal/sysproxy/       系统代理与 Linux 桌面会话环境
cmd/easyss/internal/logview/        查看日志（终端/快照）与桌面会话启动
cmd/easyss/internal/autostart/      开机自启
cmd/easyss/internal/singleton/      单实例锁
cmd/easyss/internal/selfupdatecmd/  selfupdate 子命令与产品变体
cmd/easyss-server/                  服务端入口，单文件 main.go
integration/                        客户端+服务端端到端测试（原 cmd/easyss/easyss_test.go）
client/                             客户端核心：Client 结构体
client/assets/                      嵌入的 GeoIP 数据库、直连/屏蔽列表与 wintun DLL
client/config/                      客户端配置（JSON 解析、简化模式/旧版配置转换）
client/router/                      GeoIP + 域名列表路由引擎
client/dns/                         DNS 转发服务器 + freecache 双缓存
client/proxy/                       SOCKS5/HTTP 代理服务器 + StreamHandler
client/tun/                         TUN2socks 虚拟网卡 + ICMP 代理
client/tun/scripts/                 TUN 创建/关闭脚本（//go:embed，按 GOOS 自动选择）
server/                             服务端核心：Server 结构体（TLS/certmagic）
server/config/                      服务端配置类型
server/handler/                     TCP/UDP/ICMP 请求处理 + fallback 伪装页面
server/handler/assets/fallback/     fallback 模板/CSS/内容（//go:embed：template.html + themes.json + content.json）
server/nextproxy/                   上游 SOCKS5 代理（动态 IP/域名学习）
transport/                          传输层抽象：Transport/Stream 接口
transport/http2/                    HTTP/2 传输实现（uTLS Chrome 指纹，least-active 槽位调度，懒加载扩容）
protocol/                           应用帧协议：HANDSHAKE/DATA/DATAGRAM/FIN/RST/PADDING/COVER 编解码
crypto/                             加密层：PBKDF2 KDF + HKDF key 派生 + 计数器 nonce AEAD（两阶段）
shaper/                             流量整形：分桶 padding + cover traffic 注入 + 批处理
relay/                              双向中继：Bidirectional(idleTimeout, src→dst, dst→src)
stats/                              全局原子计数器 + 快照（streams/bytes/RTT/DNS hits 等）
config/                             共享常量（默认端口、端点路径、buffer 大小等）
log/                                基于 slog 的日志，默认时区 Asia/Shanghai
util/                               工具函数（网络、文件、DNS、系统命令）
util/bytespool/                     字节缓冲池（2 的幂次分配器，最大 128KB）
docs/                               架构与不变量（architecture.md）与 README 截图（images/）
hack/                               开发/打包工具（macOS app bundle、icns 生成、自签证书示例）
pprof/                              可选 pprof HTTP 服务（127.0.0.1:6060）
version/                            构建版本信息（GitTag、BuildDate 等）
```

## 构建命令

### 本机开发（产物写在 `bin/` 根目录）

```bash
# 客户端 (Linux/Mac)
make easyss

# 客户端 (Windows)
make easyss-windows

# 服务端
make easyss-server

# 服务端 (Windows)
make easyss-server-windows

# Android AAR — 需要 JDK(javac)、Android SDK/NDK 和 gomobile/gobind：
#   go install golang.org/x/mobile/cmd/gomobile golang.org/x/mobile/cmd/gobind
#   （gomobile 通过 PATH 查找 gobind；Makefile 依次按 PATH → GOBIN → GOPATH/bin 定位 gomobile）
make easyss-android-aar

# 无系统托盘版本 (headless/Android)
make easyss-headless
```

### CI / 发布（产物写在 `bin/<os>-<arch>/` 子目录）

每个平台一个目录，不同架构不会互相覆盖，因此打包与构建顺序无关：

```bash
make build            # 全部 6 个平台的二进制：linux/windows/darwin × amd64/arm64
make pack             # build + 14 个 zip 资产（落在 bin/）
make dist             # 发布资产：pack + Android AAR（CI 的 release/nightly 用它）
make verify           # lint + test-race（发布前的显式校验）
make clean            # 只清 CI 产物；bin/ 下的本机二进制、config.json、日志不动

# 单平台
make build-linux-amd64   # bin/linux-amd64/{easyss,easyss-headless,easyss-server}
make build-linux-arm64
make build-windows-amd64 # bin/windows-amd64/{easyss.exe,easyss-server.exe}
make build-windows-arm64
make build-darwin-arm64  # bin/darwin-arm64/{Easyss.app,easyss-server}
make build-darwin-amd64
```

zip 资产名（`easyss-linux-amd64.zip` 等）与 zip 内的二进制名是客户端自更新
（`selfupdate/product.go`）与 `docker/Dockerfile` 的对外契约，改动会导致老客户端
无法自更新，不要重命名。

> `.PHONY` 只是 Makefile 的声明行。不要用 `make .PHONY` 当目标——它会把
> format/lint/test/全部构建当作前置目标跑一遍，这正是旧 CI 里重复构建的来源。

### 交叉编译示例

```bash
# Linux ARM64 headless 客户端 / 服务端
make build-linux-arm64

# macOS ARM64 / Intel 客户端与服务端（含 .app bundle）
make build-darwin-arm64
make build-darwin-amd64

# 一次性本机交叉构建仍可用（产物落在 bin/ 根目录，会被后面的构建覆盖）
GOOS=linux GOARCH=arm64 make easyss-headless
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

- `headless`：用于 headless/Android 构建，编译 `cmd/easyss/internal/app/run_headless.go` 而非 `run.go`+托盘胶水
- 注意 `cmd/easyss/internal/app/run.go`、`tray.go` 与 `cmd/easyss/internal/tray/*.go` 头部有 `//go:build !headless`
- 系统代理（`cmd/easyss/internal/sysproxy`）不是托盘专属：三条启动路径共用 `App.setupSysProxy`/`teardownSysProxy`（`cmd/easyss/internal/app/app.go`），实际是否应用由 `App.sysProxyApplied` 记录；`App.Stop`/`App.Close` 是两个退出入口，都按“撤销系统代理 → 拆 TUN → 停核心”执行——`Stop` 只撤销本进程应用过的代理，`Close` 供托盘退出/切换无条件清理上一次运行或异步开关留下的系统代理。headless 在核心启动成功后设置系统代理、退出时由 `App.Stop` 撤销，`disable_sys_proxy` 是统一开关（设置失败只记警告，因为 root/systemd 下 gsettings 与用户会话总线常常不可达）

## 配置相关

- 默认配置文件名为 `config.json`，位于二进制同目录；简化模式/旧版配置在 `LoadConfig` 中通过 `BuildSimpleConfig` 在内存里转换为 v3，不回写配置文件，也不生成 `.bak`。
- 客户端配置入口是 `client/config/config.go` 中的 `ClientConfig`，服务端是 `server/config/config.go` 中的 `FileConfig`/`ServerConfig`；`-show-config-example` 示例分别由 `client/config.ExampleConfig()`/`ExampleSimpleConfig()` 与 `server/config.ExampleConfig()` 提供。
- `timeout`、`http_port` 推导、`tun_mtu`、本地代理监听/拨号地址与证书来源判定等不变量见 [docs/architecture.md](docs/architecture.md)。
- 显示完整配置示例：`./easyss -show-config-example`

## 架构与设计文档

`AGENTS.md` 只保留构建、测试与代码约定；关键架构要点（共 19 项）与配置不变量的完整说明见 [docs/architecture.md](docs/architecture.md)。改动传输层、协议、加密、DNS 路由、TUN 生命周期或配置前，先读对应小节。

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

- 客户端使用纯 Go 系统托盘库 `github.com/gogpu/systray`（零 CGO，Windows 走 Win32、Linux 走 D-Bus SNI、macOS 走 goffi FFI）；服务端禁用 CGO。go.mod 通过 `replace` 指向 `github.com/nange/systray v0.3.0-easyss.1` 分支（import 路径不变），该分支修复了上游 issue #39——菜单打开期间 `SetMenu` 重建会把点击派发到别的菜单项；因此运行时重建菜单树（如 UWP 豁免列表）是安全的
- `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`
- **平台脚本的唯一落盘入口是 `client/tun.WriteScriptToTemp`**（内部 `normalizeScriptEOL`）：`client/tun/scripts` 的 TUN 创建/关闭脚本与 `cmd/easyss/internal/tunhelper` 提权 helper（`helper_linux.go`/`helper_darwin.go`）的脚本都必须走它，`.bat` 会被统一成 CRLF，`.sh` 原样。cmd.exe 按 OEM 代码页逐行读取批处理文件，LF 行尾在中文 Windows（OEM 代码页 936）上会让多字节注释与换行错位、注释被当成命令执行（实测 create 脚本一条配置命令都发不出去），而 `go:embed` 取的是工作区字节——Raw 单文件下载、编辑器存成 LF、第三方镜像都不经过 `.gitattributes` 的 eol 转换。`.sh` 绝不能转成 CRLF（bash 会报 `\r: command not found`）；`client/tun/scripts/scripts_test.go` 另有一条断言守仓库的 CRLF 约定
- **平台脚本的位置参数只有一个构造点：`client/tun.ScriptArgs`**（`script_args.go`）。三套布局并不相同——windows 的第 4 位是掩码、第 8 位是适配器 DNS，linux/darwin 的第 4 位是本地网关、第 8 位是本地网关 v6；darwin 的第 5 位必须是**裸** IPv6 地址（脚本自己补 `/64`），linux 的第 2 位必须是"地址/掩码"。地址拼接（`ipSub`）、IPv6 去前缀（`bareV6Addr`）与 MTU 归一化都收在里面，调用方只填 `DeviceConfig`/DNS/MTU，再用 `Create()`/`Close()`（或 `CreateFor`/`CloseFor` 指定平台）渲染。生产代码（`Manager.createTunDevAndSetIPRoute`/`closeTunDevAndDelIPRoute`、helper 的 `runCreateScript`/`runCloseScript`）与测试**共用**它，不允许再手写位置参数切片：这些字面量过去散在 12 处，抄错只会在运行时由脚本的 "failed near" 暴露。helper 侧的唯一转换点是 `cmd/easyss/internal/tunhelper/helper_unix.go` 的 `scriptArgsFor`（`proxy.TunConfig` → `tun.ScriptArgs`），它必须带上 `TunMask`，否则 fd 路径会把地址装成 `/32`、直连路径装成 `/16`（两条路径都能上网，偏差不会报错），见 `TestHelperAndDirectPathsShareTheScriptArgs`
- **TUN 拆除只有一条路径：`Manager.teardown(reason, owner)`**（`client/tun/teardown.go`）。`Owner` 显式声明"路由与系统 DNS 归谁回收"（`OwnerLocal` = 直连路径与本进程安装的一切；`OwnerHelper` = 提权 helper 的 fd 路径，主进程只停自己的引擎并关 fd），`TeardownReason` 只决定日志与错误呈现口径、**不决定做哪些步骤**；它的四个值都由 `Start`/`Stop` 真实产生（`stop`、`start-failed`、`start-cancelled`、`create-failed`）——`create-failed` 专指创建脚本失败（脚本先装地址后装路由，是唯一"必然有东西要删"的失败），由 `Start` 的 `createFailed` 标记算出，`TestCreateScriptFailureUsesItsOwnReason` 钉住它不会被退回成死枚举。是否真的执行某一步由本次会话实际做成了什么决定（`engineUp`/`deviceUp`/`dnsTouched`），`tornDown` 保证一次会话只拆一次。Start 的失败/取消路径与 `Stop()` 都收敛到这里；它们取代了 `fdMode`/`SkipRouteCleanup`/`helperSignalled` 三套互相独立又必须永远同步的隐式条件（`SkipRouteCleanup` 字段已删除，`Owner` 由 `ownerForConfig` 从 `Config.DeviceFD > 0` 唯一推导）。`session.tunOwner` 记录本次会话的所有权并传给 `verifyTeardown`，`tunDown` 的"等 helper 退出"只对 `OwnerHelper` 生效。teardown 不自己加锁：`Stop` 持有 `stopMu`，而 Start 路径绝不能拿它——`Stop` 正持有 `stopMu` 等 `<-done`，`done` 由 Start 的 defer 关闭，那样会死锁。**有两步不属于 teardown**：①engine 启动失败时由 `Start` 自己调 `engine.Stop` 释放它可能已打开的设备（此时 `engineUp` 尚未置位，teardown 不会做；tun2socks 的 `engine.Start` 先打开设备再建协议栈，失败路径不清理，见 #550/#552）；②fd 路径上的裸 fd 由 `Start` 在**能证明它还没进引擎**的两处早退点关闭（`releaseUnownedFD`：进 `engine.Start` 之前的取消失败，与 `validateEngineKey` 拒绝配置）。一旦进入 `engine.Start`，fd 归属就交给上游（`parseDevice` 可能已把它包装成设备），失败由 `engine.Stop` 兜底，本进程不再插手——按 fd 号猜"这是不是我的设备"是不可靠的：两个独立 socket 的 `ino`/`dev` 都是 0，同一字符设备的两次打开 `dev/ino/rdev/mode` 完全相同，任何身份核对都会在号码复用时误关别人的 fd。为了让"引擎失败"必然发生在 fd 已交出之后，`validateEngineKey`（`engine_key.go`）会在 `engine.Insert` 之前把 `engine.Start` 在 `parseDevice` 之前必然拒绝的配置先拒掉——即 `LogLevel`（`log.ParseLevel`）、小于 1s 的 `UDPTimeout`、以及 `Socks5Addr`（复刻上游 `parseProxy` 的 `url.Parse` + `proxy.Parse`；`Key.Interface` 与 `Key.RestAPI` 在本项目恒为空，故只有这三项）。校验只读入参、无副作用
- **`Manager` 的会话状态在 `New` 里就建好，`Start` 只认领它**：`Start` 由调用方派发的 goroutine 执行（`session.startTunEngine`），从启用路径返回到那个 goroutine 真正进入 `Start` 之间有一个调度窗口，托盘的下一次点击可以在窗口内到达 `Stop`。若 `ctx`/`cancel` 只在 `Start` 里创建，`Stop` 在那个窗口只会看到"从未启动"并直接返回，而 `Start` 随后照常把引擎、路由与 DNS 全部建立起来——session 那边已经把 manager 收走并发布了 `EnableTun2socks=false`：界面说关了、流量还在隧道里，而且再没有人持有它去停（下一次点击会新建一套，engine 的包级默认设备被覆盖，前一套再也停不掉）。因此 `Stop` 无条件落下 `cancel()`，只在 `started` 时等 `done`（两者在 `mu` 下一起快照），并且同一个 manager 只允许 `Start` 一次。回归测试见 `TestManagerStopBeforeStartGoroutineRuns` 与 `TestFaultStopRacesWithStart`


## 其他注意事项

- 日志约定：服务端每条 TCP/ICMP 流只保留入口 `[SERVER] proxy` 一条 Info 与结束时的 `logHandlerResult` 一条结果日志；UDP 会话的连接/路由变化事件（`[UDP] upstream connected`、`[UDP_DNS]`）仍按原级别保留，因为一条会话可能重绑多次。客户端流内生命周期用 Debug，失败由入口（SOCKS5/HTTP）记录一次。handler 内部不要为拨号/连接/失败再打 Info/Error；需要区分失败阶段时用错误包装（`fmt.Errorf("...: %w", err)`）或 `streamResult` 携带
- 测试注入约定：**不新增包级可变函数钩子**（`var x = func...`），一律用构造器参数、结构体字段或接口注入；测试只改自己构造的实例（`client.sysDeps`、`tun.platform`、`handler.outboundDeps`、`runner.options`、`appDeps`、`tunhelper` 的 `ops`（包内测试）、`sysproxy.State`、`dns.systemServers` 等）。生产默认值由构造器或 `defaultXxx()` 填入，**零值不回落**：新增依赖字段后忘了填是编译期就能看见的 nil 调用，而不是悄悄走生产实现。唯一例外是 `client.sysDeps` 的 nil 字段——它的 `dialBound` 默认值必须引用所属 `Client`，没法在结构体字面量里填。`t.Parallel` 已按包启用；仍需串行的只有共享进程级状态的测试（fd 号、全局 logger、`scripts.*`、`t.Setenv`、真实端口），它们在文件顶部或测试函数上注明原因
- 导入别名约定：根 `config` 包（默认值、`Timeouts`、`SimpleConfig`）按包名裸导入，不写 `sharedconfig` 之类的别名；同一文件还要引入 `client/config` 或 `server/config` 时，把别名给后者（`clientconfig` / `serverconfig`），让 `config.` 在整仓恒定指向根包。同一个包内 `config.` 只能指向一个包，不得按文件各取所需
- 注释约定：代码注释只写"读代码看不出来、写错会静默出错"的两类事实——顺序/锁/生命周期约束，以及外部系统行为或跨包契约。不写代码演进史（"过去…现在…"、"取代了某某"），不写枚举式清单（"只有这五个方法会写这个字段"）——这类表述一旦过时就成了错误文档；设计取舍与历史写在 commit message 或本文件。单个注释块不超过 3 行，函数名已经说清楚的不要再加 godoc
- 始终使用简体中文回复我
- git commit 信息使用英文，尽量简洁，格式参考 git log 历史记录
- 在用户没有明确要求提交代码前，都不提交代码
- 提交代码前，先执行`make lint`，检查代码风格，存在问题则需要先修复再提交代码
- 当用户要求提交PR时，需要在单独的分支提交代码并推送，PR标题采用英文，PR描述使用中文
