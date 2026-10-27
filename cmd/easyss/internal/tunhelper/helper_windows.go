//go:build windows

package tunhelper

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/nange/easyss/v3/client/proxy"
	"github.com/nange/easyss/v3/client/tun"
	"github.com/nange/easyss/v3/log"
	"github.com/nange/easyss/v3/protocol"
)

const (
	tunControlDialTimeout = 5 * time.Second
	tunControlIOTimeout   = 5 * time.Second
)

// runTunHelper 在 Windows 上以提权进程运行完整的 tun2socks 引擎：wintun 适配器只能由
// 管理员创建，普通权限的主进程无法安全地接管设备句柄，因此设备、引擎与路由都随 helper
// 一起运行，主进程只通过控制连接管理生命周期。
func runTunHelper(opts helperOptions) int {
	if opts.httpAddr == "" || opts.controlAddr == "" || opts.controlToken == "" {
		fmt.Fprintln(os.Stderr, "[TUN-HELPER] missing required flags")
		return 1
	}

	// 尽早初始化日志器，错误才会进日志文件，而不是经由 stderr 丢到 windowsgui 的虚空。
	log.Init(log.Config{FilePath: opts.logFile, Level: opts.logLevel})

	conn, err := net.DialTimeout("tcp", opts.controlAddr, tunControlDialTimeout)
	if err != nil {
		log.Error("[TUN-HELPER] dial control", "addr", opts.controlAddr, "err", err)
		return 1
	}
	defer conn.Close() //nolint:errcheck

	if err := writeControlLine(conn, opts.controlToken); err != nil {
		log.Error("[TUN-HELPER] send control token", "err", err)
		return 1
	}
	// 父进程确认 token 后才继续：超时/EOF 说明父进程已放弃等待，此时绝不能再去装路由。
	if err := readControlAck(conn); err != nil {
		log.Error("[TUN-HELPER] wait for control ack", "err", err)
		return 1
	}

	// 先起父进程存活监视线程再取配置：父进程在 fetch/Start 期间超时退出时，helper
	// 不能继续把路由装上再等一个已经不存在的父进程。
	parentGone := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, conn)
		close(parentGone)
	}()

	cfg, err := fetchTunConfig(opts.httpAddr)
	if err != nil {
		_ = writeControlLine(conn, "ERROR "+controlFailure(err))
		log.Error("[TUN-HELPER] fetch tun config", "err", err)
		return 1
	}

	mgr := tun.New(tunConfigFromProxy(cfg, opts.logLevel))
	// helper 没有主进程的 router/StreamHandler，ICMP 分类与代理回环到主进程的
	// /icmp/* 端点；否则 tun2socks 会对所有 IPv4 ping 伪造 echo reply。
	icmpBackend := newHTTPICMPBackend(opts.httpAddr)
	icmpHandler := tun.NewICMPHandlerWithClassifier(icmpBackend.Classify)
	icmpHandler.SetProxy(icmpBackend, protocol.Method(0))
	mgr.SetICMPHandler(icmpHandler)

	stopped := make(chan struct{})
	go func() {
		<-parentGone
		mgr.Stop()
		close(stopped)
	}()

	if err := mgr.Start(); err != nil {
		if errors.Is(err, context.Canceled) {
			// 父进程关闭控制连接触发的 Stop 是正常退出，不是失败；否则 Wait 会报告 exit code 1。
			log.Info("[TUN-HELPER] start cancelled by parent")
			return 0
		}
		_ = writeControlLine(conn, "ERROR "+controlFailure(fmt.Errorf("start tun engine: %w", err)))
		log.Error("[TUN-HELPER] start tun engine", "err", err)
		return 1
	}

	// READY 只在路由与引擎都就位后发送：主进程据此放行 forward DNS 并保持直连拨号绑定。
	if err := writeControlLine(conn, "READY"); err != nil {
		log.Error("[TUN-HELPER] send ready", "err", err)
		mgr.Stop()
		return 1
	}

	<-stopped
	mgr.Stop()
	return 0
}

// tunConfigFromProxy 把主进程下发的 TUN 配置映射成独立引擎的启动参数。接口名不在这里
// 传递：helper 与主进程各自用默认路由探测同一个物理接口，跨进程传值反而可能过期。
func tunConfigFromProxy(cfg *proxy.TunConfig, logLevel string) tun.Config {
	return tun.Config{
		Socks5Addr:     cfg.Socks5Addr,
		Device:         cfg.Device,
		MTU:            cfg.MTU,
		LogLevel:       logLevel,
		TunIP:          cfg.TunIP,
		TunGW:          cfg.TunGW,
		TunMask:        cfg.TunMask,
		TunIPV6Sub:     cfg.TunIPV6Sub,
		TunGWV6:        cfg.TunGWV6,
		ServerIPV6:     cfg.ServerIPV6,
		LocalGateway:   cfg.LocalGateway,
		LocalGatewayV6: cfg.LocalGatewayV6,
		DNSServer:      cfg.DNSAddr,
	}
}

func writeControlLine(conn net.Conn, line string) error {
	_ = conn.SetWriteDeadline(time.Now().Add(tunControlIOTimeout))
	defer conn.SetWriteDeadline(time.Time{}) //nolint:errcheck
	_, err := io.WriteString(conn, line+"\n")
	return err
}

func readControlAck(conn net.Conn) error {
	_ = conn.SetReadDeadline(time.Now().Add(tunControlDialTimeout))
	defer conn.SetReadDeadline(time.Time{}) //nolint:errcheck

	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return err
	}
	if ack := strings.TrimSpace(line); ack != "go" {
		return fmt.Errorf("unexpected control ack %q", ack)
	}
	return nil
}

func controlFailure(err error) string {
	if payload := failurePayload(err); len(payload) > 0 {
		return string(payload)
	}
	return "unknown error"
}
