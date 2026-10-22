# 平台构建、启动路径与 TUN 约束

本文件由 [AGENTS.md](../AGENTS.md) 拆出，记录平台打包、启动路径与 TUN 生命周期中读代码不易看出、写错会静默出错的约束；配置与协议不变量见 [architecture.md](architecture.md)。修改 `cmd/easyss`、`client/tun` 或平台脚本之前，先读对应小节。

## Windows 构建

- 客户端使用纯 Go 系统托盘库 `github.com/gogpu/systray`（零 CGO，Windows 走 Win32、Linux 走 D-Bus SNI、macOS 走 goffi FFI）；服务端禁用 CGO。go.mod 通过 `replace` 指向 `github.com/nange/systray v0.3.0-easyss.1` 分支（import 路径不变），该分支修复了上游 issue #39——菜单打开期间 `SetMenu` 重建会把点击派发到别的菜单项；因此运行时重建菜单树（如 UWP 豁免列表）是安全的
- `-H windowsgui` 标志以隐藏控制台窗口
- `.gitignore` 规则 `cmd/easyss/easyss*` 排除二进制但保留 `easyss_windows.syso`

## 启动路径与系统代理

- 系统代理（`cmd/easyss/internal/sysproxy`）不是托盘专属：三条启动路径共用 `App.setupSysProxy`/`teardownSysProxy`（`cmd/easyss/internal/app/app.go`），实际是否应用由 `App.sysProxyApplied` 记录；`App.Stop`/`App.Close` 是两个退出入口，都按“撤销系统代理 → 拆 TUN → 停核心”执行——`Stop` 只撤销本进程应用过的代理，`Close` 供托盘退出/切换无条件清理上一次运行或异步开关留下的系统代理。headless 在核心启动成功后设置系统代理、退出时由 `App.Stop` 撤销，`disable_sys_proxy` 是统一开关（设置失败只记警告，因为 root/systemd 下 gsettings 与用户会话总线常常不可达）

## TUN 平台脚本

- **平台脚本的唯一落盘入口是 `client/tun.WriteScriptToTemp`**（内部 `normalizeScriptEOL`）：`client/tun/scripts` 的 TUN 创建/关闭脚本与 `cmd/easyss/internal/tunhelper` 提权 helper（`helper_linux.go`/`helper_darwin.go`）的脚本都必须走它，`.bat` 会被统一成 CRLF，`.sh` 原样。cmd.exe 按 OEM 代码页逐行读取批处理文件，LF 行尾在中文 Windows（OEM 代码页 936）上会让多字节注释与换行错位、注释被当成命令执行（实测 create 脚本一条配置命令都发不出去），而 `go:embed` 取的是工作区字节——Raw 单文件下载、编辑器存成 LF、第三方镜像都不经过 `.gitattributes` 的 eol 转换。`.sh` 绝不能转成 CRLF（bash 会报 `\r: command not found`）；`client/tun/scripts/scripts_test.go` 另有一条断言守仓库的 CRLF 约定
- **平台脚本的位置参数只有一个构造点：`client/tun.ScriptArgs`**（`script_args.go`）。三套布局并不相同——windows 的第 4 位是掩码、第 8 位是适配器 DNS，linux/darwin 的第 4 位是本地网关、第 8 位是本地网关 v6；darwin 的第 5 位必须是**裸** IPv6 地址（脚本自己补 `/64`），linux 的第 2 位必须是"地址/掩码"。地址拼接（`ipSub`）、IPv6 去前缀（`bareV6Addr`）与 MTU 归一化都收在里面，调用方只填 `DeviceConfig`/DNS/MTU，再用 `Create()`/`Close()`（或 `CreateFor`/`CloseFor` 指定平台）渲染。生产代码（`Manager.createTunDevAndSetIPRoute`/`closeTunDevAndDelIPRoute`、helper 的 `runCreateScript`/`runCloseScript`）与测试**共用**它，不允许再手写位置参数切片：这些字面量过去散在 12 处，抄错只会在运行时由脚本的 "failed near" 暴露。helper 侧的唯一转换点是 `cmd/easyss/internal/tunhelper/helper_unix.go` 的 `scriptArgsFor`（`proxy.TunConfig` → `tun.ScriptArgs`），它必须带上 `TunMask`，否则 fd 路径会把地址装成 `/32`、直连路径装成 `/16`（两条路径都能上网，偏差不会报错），见 `TestHelperAndDirectPathsShareTheScriptArgs`

## TUN 生命周期

- **TUN 拆除只有一条路径：`Manager.teardown(reason, owner)`**（`client/tun/teardown.go`）。`Owner` 显式声明"路由与系统 DNS 归谁回收"（`OwnerLocal` = 直连路径与本进程安装的一切；`OwnerHelper` = 提权 helper 的 fd 路径，主进程只停自己的引擎并关 fd），`TeardownReason` 只决定日志与错误呈现口径、**不决定做哪些步骤**；它的四个值都由 `Start`/`Stop` 真实产生（`stop`、`start-failed`、`start-cancelled`、`create-failed`）——`create-failed` 专指创建脚本失败（脚本先装地址后装路由，是唯一"必然有东西要删"的失败），由 `Start` 的 `createFailed` 标记算出，`TestCreateScriptFailureUsesItsOwnReason` 钉住它不会被退回成死枚举。是否真的执行某一步由本次会话实际做成了什么决定（`engineUp`/`deviceUp`/`dnsTouched`），`tornDown` 保证一次会话只拆一次。Start 的失败/取消路径与 `Stop()` 都收敛到这里；它们取代了 `fdMode`/`SkipRouteCleanup`/`helperSignalled` 三套互相独立又必须永远同步的隐式条件（`SkipRouteCleanup` 字段已删除，`Owner` 由 `ownerForConfig` 从 `Config.DeviceFD > 0` 唯一推导）。`session.tunOwner` 记录本次会话的所有权并传给 `verifyTeardown`，`tunDown` 的"等 helper 退出"只对 `OwnerHelper` 生效。teardown 不自己加锁：`Stop` 持有 `stopMu`，而 Start 路径绝不能拿它——`Stop` 正持有 `stopMu` 等 `<-done`，`done` 由 Start 的 defer 关闭，那样会死锁。**有两步不属于 teardown**：①engine 启动失败时由 `Start` 自己调 `engine.Stop` 释放它可能已打开的设备（此时 `engineUp` 尚未置位，teardown 不会做；tun2socks 的 `engine.Start` 先打开设备再建协议栈，失败路径不清理，见 #550/#552）；②fd 路径上的裸 fd 由 `Start` 在**能证明它还没进引擎**的两处早退点关闭（`releaseUnownedFD`：进 `engine.Start` 之前的取消失败，与 `validateEngineKey` 拒绝配置）。一旦进入 `engine.Start`，fd 归属就交给上游（`parseDevice` 可能已把它包装成设备），失败由 `engine.Stop` 兜底，本进程不再插手——按 fd 号猜"这是不是我的设备"是不可靠的：两个独立 socket 的 `ino`/`dev` 都是 0，同一字符设备的两次打开 `dev/ino/rdev/mode` 完全相同，任何身份核对都会在号码复用时误关别人的 fd。为了让"引擎失败"必然发生在 fd 已交出之后，`validateEngineKey`（`engine_key.go`）会在 `engine.Insert` 之前把 `engine.Start` 在 `parseDevice` 之前必然拒绝的配置先拒掉——即 `LogLevel`（`log.ParseLevel`）、小于 1s 的 `UDPTimeout`、以及 `Socks5Addr`（复刻上游 `parseProxy` 的 `url.Parse` + `proxy.Parse`；`Key.Interface` 与 `Key.RestAPI` 在本项目恒为空，故只有这三项）。校验只读入参、无副作用
- **`Manager` 的会话状态在 `New` 里就建好，`Start` 只认领它**：`Start` 由调用方派发的 goroutine 执行（`session.startTunEngine`），从启用路径返回到那个 goroutine 真正进入 `Start` 之间有一个调度窗口，托盘的下一次点击可以在窗口内到达 `Stop`。若 `ctx`/`cancel` 只在 `Start` 里创建，`Stop` 在那个窗口只会看到"从未启动"并直接返回，而 `Start` 随后照常把引擎、路由与 DNS 全部建立起来——session 那边已经把 manager 收走并发布了 `EnableTun2socks=false`：界面说关了、流量还在隧道里，而且再没有人持有它去停（下一次点击会新建一套，engine 的包级默认设备被覆盖，前一套再也停不掉）。因此 `Stop` 无条件落下 `cancel()`，只在 `started` 时等 `done`（两者在 `mu` 下一起快照），并且同一个 manager 只允许 `Start` 一次。回归测试见 `TestManagerStopBeforeStartGoroutineRuns` 与 `TestFaultStopRacesWithStart`
