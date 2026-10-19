package proxy

import (
	"errors"
	"net"

	"github.com/nange/easyss/v3/log"
)

// Start 自行绑定监听地址并开始服务，直到监听器被关闭（见 Close）。
//
// 它是 Serve(net.Listen(...)) 的便捷形式；runner 使用 Serve 直接交入它在启动
// 主 goroutine 上同步绑定好的监听器，使"端口被占"在 Run 返回之前就以错误暴露。
func (s *Socks5Server) Start() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	return s.Serve(ln)
}

// Serve 在调用方提供的监听器上服务，直到它被关闭（见 Close）。
//
// 监听器的所有权转移给本服务器：Close 会关闭它。调用方因此必须在**启动主
// goroutine 上**完成绑定并把错误返回给启动路径，而不是在后台 goroutine 里
// Listen 后只记日志——那正是"UI 已启动、代理却不可用"的来源。
//
// 与 Close 的竞争由一个互斥量裁决：Close 先跑则本函数拿到的监听器立即释放并
// 正常返回，绝不留下无人释放的端口。因此不需要调用方事先声明"我要启动了"。
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

// Close 关闭本服务器持有的资源：TCP 监听器、UDP 中继 socket 与全部 UDP 会话
// （代理交换与直连 socket）。它刻意不关闭借用的依赖：handler（StreamHandler）、
// router、directDialContext 与 DNSCache 都由 runner 持有并与 HTTP 入口共用
// （见 Socks5Options 的字段注释）。
//
// 已接受的 TCP 连接不在这里终止：Serve 逐个派发 handler，但不强制中断它们，
// 在飞中继靠最后关闭传输层（client.Client.Close）收尾。
//
// 幂等且有界：只关闭 socket，不做任何等待，因此不存在"启动后立刻关闭"需要后台
// 补关闭的情形。
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
		// 关闭全部 UDP 会话（代理交换与直连 socket）。正在创建中的交换由创建者
		// 自己回收：OpenExchange 返回后它会检查关闭标志，关闭交换并移除工厂条目
		// （参见 udpPool.acquireExchange）。
		if s.udp != nil {
			s.udp.close()
		}
	})
	return s.closeErr
}
