package proxy

import (
	"errors"
	"net"

	"github.com/nange/easyss/v3/log"
)

// 自行绑定监听并开始服务；runner 用 Serve 直接交入在主 goroutine 上同步绑定的监听器，
// 让"端口被占"在 Run 返回前就暴露。
func (s *Socks5Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// 监听器所有权转移给本服务器（Close 会关闭它）。绑定必须在启动主 goroutine 上完成并把
// 错误返回给启动路径——后台 goroutine 里 Listen 后只记日志，正是"UI 已启动、代理不可用"。
func (s *Socks5Server) Serve(ln net.Listener) error {
	s.udp.start()

	s.listenerMu.Lock()
	if s.closed {
		s.listenerMu.Unlock()
		ln.Close() //nolint:errcheck
		return nil
	}
	s.listener = ln
	s.listenerMu.Unlock()

	log.Info("[SOCKS5] listening", "addr", ln.Addr().String())
	if err := s.srv.Serve(ln); err != nil && !errors.Is(err, net.ErrClosed) {
		return err
	}
	return nil
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
