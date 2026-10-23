package proxy

import (
	"errors"
	"net"

	"github.com/nange/easyss/v3/log"
)

// 自行绑定监听并开始服务；runner 用 Serve 直接交入在主 goroutine 上同步绑定的监听器，
// 让"端口被占"在 Run 返回前就暴露。
func (s *Socks5Server) Start() error {
	ln, err := s.bind()
	if err != nil {
		return err
	}
	if ln == nil {
		// Close 先跑：监听器已就地释放，不留下无人释放的端口。
		return nil
	}
	return s.Serve(ln)
}

// Serve 在调用方提供的监听器上服务，直到该监听器被关闭。监听器所有权**转移**给本
// 服务器（Close 会关闭它），因此"端口被占"必须在启动主 goroutine 上就暴露——后台
// goroutine 里 Listen 后只记日志，正是"UI 已启动、代理不可用"。
func (s *Socks5Server) Serve(ln net.Listener) error {
	s.listenerMu.Lock()
	if s.closed {
		s.listenerMu.Unlock()
		ln.Close() //nolint:errcheck
		return nil
	}
	s.listener = ln
	s.listenerMu.Unlock()
	return s.serve(ln)
}

// ServeBorrowed 在**借用**的监听器上服务：不登记、Close 也不会关闭它，生命周期由调用方
// 负责（VPN 对端面用的是 tailcat 在 gVisor netstack 里的监听器，本来就不属于宿主）。
func (s *Socks5Server) ServeBorrowed(ln net.Listener) error { return s.serve(ln) }

func (s *Socks5Server) serve(ln net.Listener) error {
	// udpPool.start 不是幂等的（每次调用都会起一个清理 goroutine），因此它必须留在这里。
	s.udp.start()

	log.Info("[SOCKS5] serving", "addr", ln.Addr().String())
	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
}

// bind 创建监听器并在 listenerMu 下登记，使 Close 能关闭它。返回 (nil, nil) 表示
// 服务器在绑定期间已被关闭——监听器已在本地释放，调用方应当安静地结束。
func (s *Socks5Server) bind() (net.Listener, error) {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return nil, err
	}

	s.listenerMu.Lock()
	if s.closed {
		s.listenerMu.Unlock()
		ln.Close() //nolint:errcheck
		return nil, nil
	}
	s.listener = ln
	s.listenerMu.Unlock()

	return ln, nil
}

// 关闭本服务器持有的资源，刻意不关闭借用的 handler/router/directDialContext/DNSCache
// （由 runner 持有并与 HTTP 入口共用）；已接受的 TCP 连接不在这里终止，由 client.Client.Close 收尾。
func (s *Socks5Server) Close() error {
	s.closeOnce.Do(func() {
		s.listenerMu.Lock()
		s.closed = true
		ln := s.listener
		s.listener = nil
		s.listenerMu.Unlock()

		if ln != nil {
			if err := ln.Close(); err != nil && !errors.Is(err, net.ErrClosed) {
				s.closeErr = err
			}
		}

		s.closeUDPRelays()
		// 关闭全部 UDP 会话；正在创建中的交换由创建者自己回收——OpenExchange 返回后
		// 它会检查关闭标志并关闭交换（参见 udpPool.acquireExchange）。
		if s.udp != nil {
			s.udp.close()
		}
	})
	return s.closeErr
}
