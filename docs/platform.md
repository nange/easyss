# 平台构建、启动路径与 TUN 约束

本文件与 [architecture.md](architecture.md) 只记录平台与 TUN 相关、读代码不易看出、写错会静默出错的约束；目录与构建命令见 [AGENTS.md](../AGENTS.md)。

## Windows 构建

- 客户端用纯 Go 托盘库 `github.com/gogpu/systray`（零 CGO）；go.mod 用 `replace` 指向 `nange/systray v0.3.0-easyss.1`，该分支修复了菜单打开期间 `SetMenu` 重建把点击派发到别的菜单项的问题，因此运行时重建菜单树是安全的。服务端禁用 CGO。
- `-H windowsgui` 隐藏控制台窗口。

## Windows 提权与开机自启

- **manifest 是 `asInvoker`**（`build/windows/manifest.xml`，改动后必须 `make syso`）：`requireAdministrator` 会让非管理员账户每次启动都要输管理员密码，登录路径也起不来。进程默认是普通权限，只有用户授权提权（或账户已提权）才有管理员令牌。
- **开机自启只写 `HKCU\...\Run`**：普通权限可写，因此自启能注册成功；登录后进程也是普通权限，配置里 `enable_tun2socks` 为真时启动路径会跳过 TUN 并提示（`session.start` 的 `!App.deps.isElevated()` 分支）。值必须整体加引号，否则带空格路径会被 ShellExecute 拆分。
- **开 TUN 的提权路径是"以管理员权限重启"**：托盘 `requestTunElevation` 先过 `canStartTunNow`（网络没就绪就不必让用户过一遍 UAC），再 `ShellExecuteExW("runas")` 重启自身，参数 `-elevated-restart=server=<idx>,sysproxy=<on|off>,rule=<rule>,log=<level> -enable-tun2socks -c <abs config>`。服务器选择、浏览器代理开关、规则与日志级别只活在旧实例的内存快照/菜单里，配置文件里没有，必须随这条命令行交接（载荷只放整数与枚举，没有转义规则，配置路径仍走独立 flag）；新实例在 `main` 里、`log.Init` 之前用 `RestartState.Apply` 写回快照。`-elevated-restart` 出现即表示要重启，空载荷同样有效（`IsBoolFlag` + `Set` 里置位），否则新实例会按普通启动抢锁失败退出；带载荷只能用等号形式，空格形式会被 `flag` 当位置参数丢掉。UAC 授权成功后旧实例立即走自己的退出流程（撤系统代理 → 拆 TUN → 停核心），进程退出即释放互斥量；新实例带 `-elevated-restart` 时轮询互斥量等旧实例退完（上限 20s），**把 `ERROR_ACCESS_DENIED` 也当作"锁仍被占用"**——标准用户输入管理员凭据（over-the-shoulder）后新进程属于另一个账户，打不开旧实例按默认 DACL 创建的对象，只能等。超时后弹 MessageBox 再退出：`-H windowsgui` 没有控制台，静默退出等于"点了 UAC 之后什么都没发生"。UAC 被取消时 `ShellExecuteExW` 返回 `ERROR_CANCELLED`，勾选必须回滚。
- **单实例互斥量必须在 `Local\` 命名空间**：创建 `Global\` 对象要 `SeCreateGlobalPrivilege`，非提权进程（包括管理员组的普通令牌）会拿到 `ACCESS_DENIED`，而 `Acquire` 把它当致命错误 `os.Exit(1)`——`-H windowsgui` 下表现为"勾了开机启动，登录后托盘不出现"。
- **UWP 回环豁免（`CheckNetIsolation`）要管理员权限**：普通权限下子菜单只显示一条说明，不列出可点击的应用程序。
- 标准用户输入管理员凭据提权时（over-the-shoulder），进程的 `HKCU` 是那个管理员账户：TUN 不受影响（改的是机器级路由/DNS），但系统代理会写进管理员账户的 Internet Settings，当前用户的浏览器不会走代理；从这次重启里改的"开机启动"也会落到管理员的 Run 键上。这是 Windows 的账户边界，无法规避。
- 已知限制：登录自启是普通权限，TUN 不会在登录时自动开启；需要"登录即全局代理"的账户可用任务计划程序以最高权限启动，本仓库尚未内置该注册。

## 启动路径与系统代理

- 系统代理不是托盘专属：三条启动路径共用 `App.setupSysProxy`/`teardownSysProxy`，是否应用由 `App.sysProxyApplied` 记录。两个退出入口都按"撤销系统代理 → 拆 TUN → 停核心"执行：`Stop` 只撤销本进程应用过的代理，`Close` 无条件清理（托盘退出/切换，清掉上一次运行或异步开关留下的代理）。headless 在核心启动成功后设置、退出时由 `Stop` 撤销；`disable_sys_proxy` 是统一开关，设置失败只记警告（root/systemd 下 gsettings 与会话总线常不可达）。

## TUN 平台脚本

- **唯一落盘入口 `client/tun.WriteScriptToTemp`**（内部 `normalizeScriptEOL`）：`client/tun/scripts` 与 tunhelper 的脚本都必须走它，`.bat` 统一 CRLF、`.sh` 原样。cmd.exe 按 OEM 代码页逐行读批处理，LF 会让中文注释与换行错位、注释被当命令执行；`go:embed` 取的是工作区原始字节（Raw 下载/编辑器/镜像都不经过 `.gitattributes`）。`.sh` 绝不能 CRLF（bash 会报 `\r: command not found`）。
- **位置参数唯一构造点 `client/tun.ScriptArgs`**（`script_args.go`）：三套布局不同——windows 第 4 位是掩码、第 8 位是适配器 DNS；linux/darwin 第 4 位是本地网关、第 8 位是网关 v6；darwin 第 5 位必须是裸 IPv6（脚本自己补 `/64`），linux 第 2 位是"地址/掩码"。`ipSub`/`bareV6Addr`/MTU 归一化都收在里面，调用方只填 `DeviceConfig`/DNS/MTU，用 `Create`/`Close`（或 `CreateFor`/`CloseFor`）渲染。生产代码与测试共用它，不得手写位置参数切片（抄错只会在运行时由脚本 "failed near" 暴露）。helper 侧唯一转换点 `scriptArgsFor` 必须带 `TunMask`，否则 fd 路径装成 `/32`、直连装成 `/16`（都能上网，不报错），见 `TestHelperAndDirectPathsShareTheScriptArgs`。

## TUN 生命周期

- **拆除只有一条路径 `Manager.teardown(reason, owner)`**（`teardown.go`）。`Owner` 声明路由与系统 DNS 归谁回收（由 `ownerForConfig` 从 `DeviceFD > 0` 唯一推导）：`OwnerLocal` = 直连路径与本进程安装的一切；`OwnerHelper` = fd 路径，主进程只停引擎并关 fd。`TeardownReason` 只决定日志/错误口径，不决定步骤：`create-failed` 专指创建脚本失败（唯一"必然有东西要删"的失败），由 `Start` 在 `errors.Is(err, ErrCreateDevice)` 时选出（创建脚本失败在 `tun.go` 里包成 `ErrCreateDevice`），`TestCreateScriptFailureUsesItsOwnReason` 钉住它；`start-cancelled` 由取消产生。实际执行哪步由本次会话做成什么决定（`engineUp`/`deviceUp`/`dnsTouched`），`tornDown` 保证只拆一次。`session.tunOwner` 记录所有权并传给 `verifyTeardown`；`tunDown` 的"等 helper 退出"只对 `OwnerHelper` 生效。
- teardown 不加锁：`Stop` 持有 `stopMu` 并等 `<-done`，而 `done` 由 `Start` 的 defer 关闭；Start 路径绝不能拿 `stopMu`，否则死锁。
- **两步不属于 teardown**：①engine 启动失败时 `Start` 自己调 `engine.Stop` 释放设备（此时 `engineUp` 未置位）；②fd 路径的裸 fd 只在能证明尚未进引擎的两处早退点关闭（`releaseUnownedFD`、`validateEngineKey` 拒绝配置）。一旦进入 `engine.Start`，fd 归上游，失败由 `engine.Stop` 兜底；不要按 fd 号猜归属（独立 socket 的 `ino`/`dev` 为 0，同一设备两次打开身份完全相同，号码复用会误关别人的 fd）。为保证"引擎失败必然发生在 fd 交出之后"，`validateEngineKey` 在 `engine.Insert` 前拒绝 `engine.Start` 必然拒绝的配置（`LogLevel`、小于 1s 的 `UDPTimeout`、`Socks5Addr`），只读入参。
- **Manager 会话状态在 `New` 里建好，`Start` 只认领**：`Start` 在调用方派发的 goroutine 里执行，启用路径返回到真正进入 `Start` 之间有调度窗口，托盘点击可在此期间到达 `Stop`。若 `ctx`/`cancel` 只在 `Start` 创建，`Stop` 会看到"未启动"直接返回，而 `Start` 随后把引擎/路由/DNS 全建起来且再无人持有——界面显示已关、流量仍在隧道里。因此 `Stop` 无条件 `cancel()`，只在 `started` 时等 `done`（两者在 `mu` 下快照），同一 manager 只允许 `Start` 一次。回归测试 `TestManagerStopBeforeStartGoroutineRuns`、`TestFaultStopRacesWithStart`。
- **退出路径的 `session.stop` 也执行完整拆除（`tunDownLocked`）**：托盘 `tunUp` 不持会话序列锁，可能插进 `App.Stop` 的 `tunDown` 与 `stop` 之间。只 `Stop()` 引擎会漏掉 `tunSession`/`tunOwner`/helper FIFO，helper 会继续持 flock、路由与系统 DNS。回归测试 `TestStopReclaimsTunInstalledAfterTunDown`。
- **启动路径安装 TUN 前要按当前偏好复核**：`sessionCfg` 是 `runCore` 之前的快照，托盘可以在这期间关掉 TUN。`startTunEngineAtStartup` 在 `tunMu` 内用 `currentConfig()` 复查（`startupTunWantedLocked`），否则用户已关闭的 TUN 又会被装上，而菜单随后按配置同步成"关"。回归测试 `TestStartupTunHonorsLatestPreference`。
