package app

import (
	"fmt"
	"io"
	"net/http"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/cmd/easyss/internal/tunhelper"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/pprof"
	"github.com/nange/easyss/v3/runner"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util"
)

// session 持有一次代理会话的运行期状态：核心、TUN 引擎与提权 helper 的句柄、
// pprof 与统计循环。
//
// 锁序：seqMu → mu → tunMu。
type session struct {
	app *App

	// mu 保护会话级字段，一次 start/stop 的全部改写都在锁内完成。
	mu sync.Mutex

	// tunMu 保护 TUN 会话字段；与 mu 分开，让 TUN 开关不被秒级的 start 挡住。
	tunMu sync.Mutex

	// seqMu 串行化整套"停→起"序列，不可重入。
	seqMu sync.Mutex

	// 读点必须只 Load 一次，否则两次读之间会被 stop 清空。
	core atomic.Pointer[runner.Core]

	pprofSrv *http.Server

	startupWarn error

	tunSkippedForNetwork bool

	statsCloser chan struct{}

	verifyTeardown func(dev tun.DeviceConfig, owner tun.Owner, helperSignalled bool) error

	// 拆除时 tunMgr 可能已经变了，启用时的设备配置要留一份。
	tunMgr         *tun.Manager
	tunSession     *tun.DeviceConfig
	tunHelperStdin io.WriteCloser

	// tunActive 是"引擎已开始转发"：adopt 时还不算，拆除一开始就清掉。forward DNS 读它。
	tunActive bool

	// 系统改动归谁回收（见 tun.Owner），必须在建立会话时写入。
	tunOwner tun.Owner
}

func newSession(app *App) *session {
	return &session{app: app, verifyTeardown: tunhelper.DefaultVerify()}
}

// 并发执行会抢同一组本地端口，因此整个"停→起"都在序列锁下。序列锁不可重入。
func (s *session) run(fn func()) {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	fn()
}

func (s *session) runErr(fn func() error) error {
	s.seqMu.Lock()
	defer s.seqMu.Unlock()
	return fn()
}

func (s *session) currentCore() *runner.Core { return s.core.Load() }

func (s *session) installCore(core *runner.Core) { s.core.Store(core) }

func (s *session) startupWarning() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startupWarn
}

// 全程持有 mu：stop 会在另一个 goroutine 上与它交错。
func (s *session) start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// 上一轮的残留会抑制新一轮的记录，必须在这里重置。
	s.startupWarn = nil
	s.tunSkippedForNetwork = false

	// 配置快照一经发布即不可变，可以安全地交给核心长期持有。
	sessionCfg := s.app.currentConfig()

	core, err := s.app.deps.runCore(sessionCfg)
	if err != nil {
		return err
	}
	s.installCore(core)
	if core.StartupWarn != nil {
		s.startupWarn = core.StartupWarn
		log.Warn("[EASYSS-V3] startup warning", "err", core.StartupWarn)
	}
	gen := coreGen.Add(1)
	domainPending := !canStartTunNow(core)

	// client.New 已按配置初值播种拨号器的 TUN 状态（mobile 依赖它），但本会话的引擎此刻还
	// 没开始转发：先按未生效发布，mgr.Start() 成功后才由 markTunEngineUp 置位。
	s.tunMu.Lock()
	s.syncTunStateLocked()
	s.tunMu.Unlock()

	// 偏好只是进入条件：runCore 可能耗时数秒，期间托盘可以关掉 TUN。
	// 安装前 startTunEngineAtStartup 会在 tunMu 内用当前偏好复核。
	if sessionCfg.Local.EnableTun2socks {
		// 非 root 拿不到 TUN，用户却以为全局流量已代理，必须说明原因。
		if (runtime.GOOS == "darwin" || runtime.GOOS == "linux") && !tunhelper.IsRoot() {
			log.Warn("[EASYSS-V3] tun2socks requires root; skipped (use sudo, or run with system tray for automatic elevation)")
			// 偏好落回 false，否则菜单勾选着"已开启"而 tunMgr 是 nil。
			s.app.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = false })
			s.app.notifyTunSkippedNoRoot()
		} else if !domainPending {
			// 服务端域名已预解析并写进 DNS 缓存，TUN 的 DNS 不会在它上面死锁。
			s.startTunEngineAtStartup()
		} else {
			// 服务端域名还没解析出来：此时启用 TUN 会让平台脚本把系统 DNS 指向本机转发
			// 服务器，而解析服务端域名又需要隧道本身。
			s.app.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = false })
			s.tunSkippedForNetwork = true
			log.Warn("[EASYSS-V3] server domain not resolved yet; tun2socks skipped until the network is ready")
			s.app.notifyTunSkippedNetworkUnready()
		}
	}

	if s.statsCloser != nil {
		close(s.statsCloser)
	}
	s.statsCloser = make(chan struct{})
	go s.statsLoop(s.statsCloser)

	if sessionCfg.PprofEnabled {
		s.pprofSrv = pprof.StartPprof()
	}

	s.app.watchServerDomainReady(core, gen, domainPending, s.tunSkippedForNetwork)

	return nil
}

// 先停 TUN 再停核心：TUN 依赖核心的本地代理入口。取下核心与清空 tunMgr 在同一个
// tunMu 临界区里完成，core.Stop() 才在锁外等——后到的托盘开关会看到 nil 而不是装上 TUN。
func (s *session) stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.statsCloser != nil {
		close(s.statsCloser)
		s.statsCloser = nil
	}

	s.tunMu.Lock()
	// 排队在 tunMu 上的托盘 tunUp 可能插进 App.Stop 的 tunDown 与这里之间：只停引擎会漏掉
	// tunSession/tunOwner/helper FIFO，helper 会继续持路由与系统 DNS。
	s.tunDownLocked(nil)
	core := s.core.Swap(nil)
	s.tunMu.Unlock()

	if core != nil {
		core.Stop()
	}
	if srv := s.pprofSrv; srv != nil {
		s.pprofSrv = nil
		pprof.StopPprof(srv)
	}
}

func (s *session) startTunEngineAtStartup() {
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return
	}

	// 与 tunUp 共用 tunMu：两者写同一个 tunMgr，而菜单在 start 之前就已可见。
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	if !s.startupTunWantedLocked() {
		return
	}

	mgr := tun.New(s.tunConfig())
	s.adoptTunManager(mgr, nil, tun.OwnerLocal)
	s.buildICMPHandler(core)
	s.startTunEngine(mgr, "device")
}

// startupTunWantedLocked 报告启动路径是否仍应安装 TUN。runCore 期间托盘可能已经装好
// 引擎，也可能把偏好改成 false（用户点了关闭）；两者都不能再装。必须在 tunMu 内调用。
func (s *session) startupTunWantedLocked() bool {
	return s.tunMgr == nil && s.app.currentConfig().Local.EnableTun2socks
}

// 直接创建设备（Windows，或 darwin/linux 上的 root）；全程持有 tunMu，托盘会并发开关。
func (s *session) tunUp() error {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	if s.tunMgr != nil {
		return nil
	}

	// core 检查必须早于任何状态写入：先留下 tunMgr 会让后续点击命中"已设置"保护静默返回，
	// 引擎从未运行，也再没人能 Stop 它。
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return fmt.Errorf("client not initialized")
	}

	// 偏好写配置快照、运行期状态写 core 上的开关，两者必须同时更新。
	s.app.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = true })
	mgr := tun.New(s.tunConfig())
	s.adoptTunManager(mgr, nil, tun.OwnerLocal)

	s.buildICMPHandler(core)
	s.startTunEngine(mgr, "device")

	return nil
}

// adoptTunManager 一次发布 manager、设备快照与 owner：拆除路径不应看到三者的混合状态。
// adopt 时引擎还没开始转发（tunActive 落回 false），但拨号器从这里起就必须绑定物理接口。
func (s *session) adoptTunManager(mgr *tun.Manager, dev *tun.DeviceConfig, owner tun.Owner) {
	if dev == nil {
		snapshot := mgr.DeviceConfig()
		dev = &snapshot
	}
	s.tunMgr = mgr
	s.tunSession = dev
	s.tunOwner = owner
	s.tunActive = false
	s.syncTunStateLocked()
}

// syncTunStateLocked 把两个 TUN 运行期状态发布给 client，必须在 tunMu 内调用。两者安全方向
// 相反：拨号器在路由删完前必须保持绑定，forward DNS 在引擎开始转发前必须保持拒答。
func (s *session) syncTunStateLocked() {
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return
	}
	core.Client.SetTunMode(s.tunMgr != nil)
	core.Client.SetTunForwarding(s.tunActive)
}

func (s *session) buildICMPHandler(core *runner.Core) {
	icmpHandler := tun.NewICMPHandler(core.Client.Router())
	icmpHandler.SetProxy(core.StreamHandler, s.app.methodFromServer())
	s.tunMgr.SetICMPHandler(icmpHandler)
}

// 拆除的问题只记日志和通知、不中止退出，因此不返回错误。
func (s *session) tunDown() {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()
	s.tunDownLocked(nil)
}

// want 非 nil 时要求它仍是当前会话的引擎：迟到的失败回调不能拆掉用户刚打开的 TUN。
func (s *session) tunDownLocked(want *tun.Manager) {
	if want != nil && s.tunMgr != want {
		return
	}

	// forward DNS 从这里起必须拒答：关闭脚本删掉路由之后、本函数返回之前，放行就会直连解析。
	// 拨号器的绑定不动——路由可能还在，提前解绑会把直连拨回隧道里。
	s.tunActive = false
	s.syncTunStateLocked()

	// 会话配置必须在清空 tunMgr 之前取下来：它既用于校验，也用于兜底回滚。
	dev := s.tunSession
	if dev == nil && s.tunMgr != nil {
		snapshot := s.tunMgr.DeviceConfig()
		dev = &snapshot
	}
	s.tunSession = nil

	// Owner 零值是 OwnerLocal，未显式记录的会话落在"本进程自己装的"这一侧。
	owner := s.tunOwner

	// 先停引擎：它会关闭 helper 传进来的 TUN fd，而 iproute2 删不掉仍附着在 fd 上的设备
	// （device or resource busy）。
	if s.tunMgr != nil {
		log.Info("[EASYSS-V3] tunDown: stopping tun2socks engine", "owner", owner.String())
		s.tunMgr.Stop()
		s.tunMgr = nil
	}

	// 关闭 FIFO 通知 helper：它读到 stdin EOF 后自己清理路由/DNS。
	helperSignalled := false
	if s.tunHelperStdin != nil {
		log.Info("[EASYSS-V3] tunDown: closing helper FIFO")
		s.tunHelperStdin.Close() //nolint:errcheck
		s.tunHelperStdin = nil
		helperSignalled = true
	}
	s.tunOwner = tun.OwnerLocal

	if dev != nil {
		if err := s.verifyTeardown(*dev, owner, helperSignalled); err != nil {
			log.Error("[EASYSS-V3] tunDown: TUN teardown left routes behind", "err", err)
			s.app.notifyTunTeardownProblem(
				"TUN 已停止，但系统路由表里仍残留指向 TUN 的路由，本机可能无法上网。请退出并重新启动 Easyss，或重启系统以恢复网络。详情：" + err.Error())
		}
	}

	if core := s.currentCore(); core != nil && core.HTTPServer != nil {
		core.HTTPServer.ClearTunConfig()
	}

	// tunMgr 已清空：本进程（或 helper）不再有指向 TUN 的路由要承接，拨号器才解除绑定。
	s.syncTunStateLocked()
	s.app.updateConfig(func(c *clientconfig.ClientConfig) { c.Local.EnableTun2socks = false })
}

// 启动路径与托盘开关共享的唯一 TUN 配置构造点。
func (s *session) tunConfig() tun.Config {
	core := s.currentCore()
	if core != nil && core.Client != nil {
		// 降级启动时启动期的 IPv6 解析是空值，这里补一次有界解析，否则 TUN 脚本不装 IPv6
		// 默认路由，IPv6 流量会绕过隧道。必须在 tunDNS 之前：它可能顺带发现可达的解析器。
		core.Client.RefreshServerIPV6()
	}

	// 各字段必须来自同一份配置快照。
	snap := s.app.currentConfig()
	cfg := tun.Config{
		// bind_all 时入口监听 [::]，引擎必须拨同族回环 [::1]（见 util.Socks5URI）。
		Socks5Addr: util.Socks5URI(snap.Local.BindAll, snap.Local.SocksPort),
		DNSServer:  tunDNS(),
		// 设备的真实 MTU 与 netstack 的 MTU 必须同源，否则超限包会被静默丢弃。
		MTU: snap.TunMTU(),
	}
	if core != nil && core.Client != nil {
		if ipv6 := core.Client.Router().ServerIPV6(); ipv6 != "" {
			cfg.ServerIPV6 = ipv6
		}
	}
	return cfg
}

// Manager.Start 会阻塞到平台路由脚本完成，必须允许 Stop() 在启动途中取消它。
func (s *session) startTunEngine(mgr *tun.Manager, mode string) {
	go func() {
		if err := mgr.Start(); err != nil {
			log.Error("[EASYSS-V3] tun2socks start", "mode", mode, "err", err)
			s.rollbackFailedTunStart(mgr, err)
			return
		}
		s.markTunEngineUp(mgr)
	}()
}

// 成功返回意味着引擎开始转发，此时才能放行 forward DNS 的上游查询；拨号器的绑定在 adopt
// 时已发布，这里不再改。与拆除共用 tunMu：Start 与 tunDown 交错时按 manager 身份判定。
func (s *session) markTunEngineUp(mgr *tun.Manager) {
	s.tunMu.Lock()
	defer s.tunMu.Unlock()

	if s.tunMgr != mgr {
		return
	}
	s.tunActive = true
	s.syncTunStateLocked()
}

// "核对身份 → 拆除"必须在同一个 tunMu 临界区里完成：这期间用户可能已重新打开 TUN，
// 按身份过滤才不会拆掉刚建立的会话。
func (s *session) rollbackFailedTunStart(mgr *tun.Manager, err error) {
	s.tunMu.Lock()
	if s.tunMgr != mgr {
		s.tunMu.Unlock()
		log.Info("[EASYSS-V3] tun2socks start failure ignored: its session has been replaced", "err", err)
		return
	}
	s.tunDownLocked(mgr)
	s.tunMu.Unlock()

	if s.app.ui != nil {
		s.app.ui.tunStartFailed(err)
	}
}

func (s *session) statsLoop(done <-chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.logStatsOnce()
		case <-done:
			return
		}
	}
}

func (s *session) logStatsOnce() {
	core := s.currentCore()
	if core == nil || core.Client == nil {
		return
	}
	snap := stats.Collect()
	snap.TransportStats = core.Client.Transport().Stats()
	log.Info("[STATS]",
		"uptime", snap.Uptime().Round(time.Second),
		"conns", snap.Conns,
		"priority_conns", snap.PriorityConns,
		"bulk_conns", snap.BulkConns,
		"priority_conns_status", snap.PriorityConnsStatus,
		"bulk_conns_status", snap.BulkConnsStatus,
		"active_streams", snap.ActiveStreams,
		"priority_active", snap.PriorityActiveStreams,
		"bulk_active", snap.BulkActiveStreams,
		"streams(opened)", snap.TotalStreamsOpened,
		"streams(closed)", snap.TotalStreamsClosed,
		"priority_opened", snap.PriorityStreamsOpened,
		"bulk_opened", snap.BulkStreamsOpened,
		"priority_fallback", snap.PriorityFallback,
		"bulk_fallback", snap.BulkFallback,
		"tx", stats.HumanBytes(snap.BytesSent),
		"rx", stats.HumanBytes(snap.BytesRecv),
		"raw_tx", stats.HumanBytes(snap.RawBytesSent),
		"raw_rx", stats.HumanBytes(snap.RawBytesRecv),
		"upload_speed", snap.UploadSpeedHuman,
		"download_speed", snap.DownloadSpeedHuman,
		"proxy_tcp_streams", snap.TCPConnections,
		"udp_assoc", snap.UDPAssociations,
		"dns(hit)", snap.DNSCacheHits,
		"dns(miss)", snap.DNSCacheMisses,
		"dns(proxy)", snap.DNSProxyQueries,
		"dns(direct)", snap.DNSDirectQueries,
		"padding", stats.HumanBytes(snap.PaddingBytes),
		"records", snap.RecordsWritten,
		"avg_rtt", snap.AvgRTT().Round(time.Millisecond),
		"slot_degraded", snap.SlotDegraded,
		"slot_retired_degraded", snap.SlotRetiredDegraded,
		"slot_probes", snap.SlotProbes,
		"slot_probe_get", snap.SlotProbeGet,
		"slot_probe_head", snap.SlotProbeHead,
		"slot_probe_slow", snap.SlotProbeSlow,
		"slot_grown_priority", snap.SlotGrownPriority,
		"slot_grown_bulk", snap.SlotGrownBulk,
		"conn_rotated", snap.ConnRotated,
	)
}
