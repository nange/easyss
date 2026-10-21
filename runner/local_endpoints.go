package runner

import (
	"fmt"
	"io"
	"net"

	"github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/util"
)

// localEndpoints 是 Run 在派发任何服务器 goroutine 之前同步绑定的本地监听器。
// Close 只关监听器；服务器自身的关闭仍归 Core.cleanup。
type localEndpoints struct {
	socksAddr     string
	socksDialAddr string
	httpAddr      string
	dnsAddr       string

	socksLn net.Listener
	httpLn  net.Listener
	dnsPC   net.PacketConn

	closers []io.Closer
}

func openLocalEndpoints(cfg *config.ClientConfig, opts options) (*localEndpoints, error) {
	eps := &localEndpoints{}
	if err := eps.bind(cfg, opts); err != nil {
		eps.Close()
		return nil, err
	}
	return eps, nil
}

// bind 按 socks → http → dns 的顺序同步绑定；任一步失败时已绑定的监听器由
// openLocalEndpoints 统一关闭。
func (e *localEndpoints) bind(cfg *config.ClientConfig, opts options) error {
	if cfg.Local.SocksPort > 0 {
		e.socksAddr = util.LocalProxyListenAddr(cfg.Local.BindAll, cfg.Local.SocksPort)
		e.socksDialAddr = util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.SocksPort)
		ln, err := net.Listen("tcp", e.socksAddr)
		if err != nil {
			return fmt.Errorf("socks5 server listen %s: %w", e.socksAddr, err)
		}
		e.socksLn = ln
		e.closers = append(e.closers, ln)
	}

	if cfg.Local.HTTPPort > 0 {
		if cfg.Local.SocksPort <= 0 {
			return ErrSocksRequired
		}
		e.httpAddr = util.LocalProxyListenAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
		ln, err := net.Listen("tcp", e.httpAddr)
		if err != nil {
			return fmt.Errorf("http proxy server listen %s: %w", e.httpAddr, err)
		}
		e.httpLn = ln
		e.closers = append(e.closers, ln)
	}

	if cfg.Local.EnableForwardDNS {
		e.dnsAddr = opts.forwardDNSListenAddr
		pc, err := net.ListenPacket("udp", e.dnsAddr)
		if err != nil {
			return forwardDNSListenError(e.dnsAddr, err)
		}
		e.dnsPC = pc
		e.closers = append(e.closers, pc)
	}

	return nil
}

func (e *localEndpoints) Close() {
	if e == nil {
		return
	}
	for _, closer := range e.closers {
		_ = closer.Close()
	}
	e.closers = nil
}
