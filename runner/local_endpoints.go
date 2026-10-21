package runner

import (
	"fmt"
	"net"

	clientconfig "github.com/nange/easyss/v3/client/config"
	"github.com/nange/easyss/v3/util"
)

// localEndpoints 是 Run 在派发任何服务器 goroutine 之前同步绑定的本地监听器。
// Close 只关监听器；服务器自身的关闭仍归 Core.cleanup。
type localEndpoints struct {
	socksAddr     string
	socksDialAddr string
	httpAddr      string
	dnsAddr       string // 配置监听地址；self-upstream 判定依赖它，不能用 LocalAddr 代替

	socksLn net.Listener
	httpLn  net.Listener
	dnsPC   net.PacketConn
}

// validateLocalEndpoints 只做配置校验，必须在任何监听器绑定之前调用。
func validateLocalEndpoints(cfg *clientconfig.ClientConfig) error {
	if cfg.Local.HTTPPort > 0 && cfg.Local.SocksPort <= 0 {
		return ErrSocksRequired
	}
	return nil
}

func openLocalEndpoints(cfg *clientconfig.ClientConfig, opts options) (*localEndpoints, error) {
	eps := &localEndpoints{}
	if err := eps.bind(cfg, opts); err != nil {
		eps.Close()
		return nil, err
	}
	return eps, nil
}

// bind 按 socks → http → dns 的顺序同步绑定；任一步失败时已绑定的监听器由
// openLocalEndpoints 统一关闭。配置合法性由 validateLocalEndpoints 预先保证。
func (e *localEndpoints) bind(cfg *clientconfig.ClientConfig, opts options) error {
	if cfg.Local.SocksPort > 0 {
		e.socksAddr = util.LocalProxyListenAddr(cfg.Local.BindAll, cfg.Local.SocksPort)
		e.socksDialAddr = util.LocalProxyDialAddr(cfg.Local.BindAll, cfg.Local.SocksPort)
		ln, err := net.Listen("tcp", e.socksAddr)
		if err != nil {
			return fmt.Errorf("socks5 server listen %s: %w", e.socksAddr, err)
		}
		e.socksLn = ln
	}

	if cfg.Local.HTTPPort > 0 {
		e.httpAddr = util.LocalProxyListenAddr(cfg.Local.BindAll, cfg.Local.HTTPPort)
		ln, err := net.Listen("tcp", e.httpAddr)
		if err != nil {
			return fmt.Errorf("http proxy server listen %s: %w", e.httpAddr, err)
		}
		e.httpLn = ln
	}

	if cfg.Local.EnableForwardDNS {
		e.dnsAddr = opts.forwardDNSListenAddr
		pc, err := net.ListenPacket("udp", e.dnsAddr)
		if err != nil {
			return forwardDNSListenError(e.dnsAddr, err)
		}
		e.dnsPC = pc
	}

	return nil
}

func (e *localEndpoints) Close() {
	if e == nil {
		return
	}
	if e.socksLn != nil {
		_ = e.socksLn.Close()
		e.socksLn = nil
	}
	if e.httpLn != nil {
		_ = e.httpLn.Close()
		e.httpLn = nil
	}
	if e.dnsPC != nil {
		_ = e.dnsPC.Close()
		e.dnsPC = nil
	}
}
