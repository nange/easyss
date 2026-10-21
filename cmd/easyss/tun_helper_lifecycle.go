//go:build darwin || linux

package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/util"
	"golang.org/x/sys/unix"
)

type tunHelper struct {
	cfg       *proxy.TunConfig
	ops       tunOps
	lockFile  *os.File
	fd        int
	device    string
	mtu       int
	originDNS []string
	fdSent    bool
	failure   error
}

// setup 取得配置、控制锁与设备；失败时释放已经拿到的资源，调用方只负责报告。
func (h *tunHelper) setup(httpAddr string) (step string, err error) {
	defer func() {
		if err != nil {
			h.closeLock()
		}
	}()

	cfg, err := fetchTunConfig(httpAddr)
	if err != nil {
		return "fetch tun config", err
	}
	h.cfg = cfg
	log.Info("[TUN-HELPER] config received", "device", cfg.Device)

	h.ops = defaultTunOps()
	lockFile, err := os.OpenFile(h.ops.lockPath, os.O_CREATE|os.O_RDWR, 0644)
	if err != nil {
		return "open lock file", err
	}
	h.lockFile = lockFile

	// 上一个 helper 若仍在清理，这里会阻塞到它退出、内核释放锁。
	if err := util.FlockWait(lockFile, 30*time.Second); err != nil {
		return "acquire lock", err
	}
	log.Info("[TUN-HELPER] lock acquired")

	// 必须在改动系统 DNS 之前保存原始配置。
	originDNS, err := util.SysDNS()
	if err != nil {
		log.Warn("[TUN-HELPER] read original dns", "err", err)
	}
	h.originDNS = originDNS
	log.Info("[TUN-HELPER] original dns saved", "dns", originDNS)

	// 设备由 helper 创建，tun2socks 只设 netstack 的 MTU：两侧不一致时 netstack 会静默丢弃超过
	// 自身 MTU 的包（UDP、ICMP 与 IP 分片），因此 0 值必须落到与主进程相同的默认值。
	h.mtu = config.NormalizeTunMTU(cfg.MTU)
	tunFd, actualDevice, err := openTunDevice(cfg.Device)
	if err != nil {
		return "open tun device", err
	}
	h.fd = tunFd
	h.device = actualDevice
	log.Info("[TUN-HELPER] device created", "requested", cfg.Device, "actual", actualDevice, "mtu", h.mtu)
	return "", nil
}

// configure 落地路由与系统 DNS；create 脚本失败时关闭尚未移交的设备 fd。
func (h *tunHelper) configure() error {
	// 给内核一点时间初始化接口。
	log.Info("[TUN-HELPER] waiting for kernel interface init")
	time.Sleep(200 * time.Millisecond)

	// 预清理失败只记 debug：设备刚被本进程建出并占用，linux 关闭脚本里的 `ip tuntap del` 必然
	// 失败，路由也马上会被创建脚本重写。
	log.Info("[TUN-HELPER] cleaning stale routes")
	if err := runCloseScript(h.device, scriptArgsFor(h.cfg)); err != nil {
		log.Debug("[TUN-HELPER] pre-clean routes", "device", h.device, "err", err)
	}

	log.Info("[TUN-HELPER] creating routes and configuring interface", "mtu", h.mtu)
	if err := runCreateScript(h.device, scriptArgsFor(h.cfg)); err != nil {
		_ = unix.Close(h.fd)
		return err
	}
	log.Info("[TUN-HELPER] routes and interface configured")

	if h.cfg.DNSAddr != "" {
		log.Info("[TUN-HELPER] setting system dns", "dns", h.cfg.DNSAddr)
		if err := util.SetSysDNSForTun(h.device, []string{h.cfg.DNSAddr}); err != nil {
			log.Warn("[TUN-HELPER] set dns", "err", err)
		}
	}
	return nil
}

// sendFD 把设备移交给父进程；发送失败时关闭 fd，fdSent 只在发送完成后置位。
func (h *tunHelper) sendFD(path string) error {
	log.Info("[TUN-HELPER] sending tun fd to parent", "socket", path)
	if err := sendFdToParent(path, h.fd); err != nil {
		_ = unix.Close(h.fd)
		return err
	}
	h.fdSent = true
	_ = unix.Close(h.fd)
	log.Info("[TUN-HELPER] fd sent and closed")
	return nil
}

func (h *tunHelper) keepAlive() {
	log.Info("[TUN-HELPER] ready, waiting for shutdown signal on stdin")

	// 阻塞到 stdin EOF：主进程关闭 FIFO 写端即关闭信号，主进程崩溃（含 kill -9）时内核也会关闭它。
	// 等待期间定期补装路由——macOS 在睡眠/唤醒或网络变更后可能清除非持久路由，静默禁用 TUN 模式。
	stdinDone := make(chan struct{})
	go func() {
		_, _ = io.ReadAll(os.Stdin)
		close(stdinDone)
	}()

	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-stdinDone:
			log.Info("[TUN-HELPER] received shutdown signal")
			return
		case <-ticker.C:
			if err := ensureTunRoutes(h.device, h.cfg); err != nil {
				log.Warn("[TUN-HELPER] route keep-alive check failed", "device", h.device, "err", err)
			}
			// NetworkManager 在连接变更时会重写链路 DNS 设置，可能把 DNS 默认路由交还物理链路，
			// 使解析再次绕过隧道。
			if h.cfg.DNSAddr != "" {
				if err := util.EnsureSysDNSForTun(h.device, []string{h.cfg.DNSAddr}); err != nil {
					log.Warn("[TUN-HELPER] dns keep-alive check failed", "device", h.device, "err", err)
				}
			}
		}
	}
}

// cleanup 回收路由与系统 DNS，最后释放控制锁；设备 fd 已在 configure/sendFD 中处理。
func (h *tunHelper) cleanup() {
	log.Info("[TUN-HELPER] cleaning up routes and DNS")
	if err := cleanupTunRoutes(h.ops, h.device, h.cfg); err != nil {
		log.Error("[TUN-HELPER] cleanup left TUN routes behind", "device", h.device, "err", err)
	}
	_ = util.RestoreSysDNSForTun(h.device, h.originDNS)
	h.closeLock()
	log.Info("[TUN-HELPER] cleanup done")
}

func (h *tunHelper) closeLock() {
	if h.lockFile != nil {
		_ = h.lockFile.Close()
		h.lockFile = nil
	}
}

func (h *tunHelper) fail(step string, err error) int {
	h.failure = fmt.Errorf("%s: %w", step, err)
	log.Error("[TUN-HELPER] "+step, "err", err)
	return 1
}
