package proxy

import (
	"errors"
	"net"

	"github.com/nange/easyss/v3/log"
)

// Start 创建监听器并开始服务，直到监听器被关闭（见 Close）。
//
// 监听器的绑定在调用方 goroutine 上同步完成。与上一版实现的区别：库只提供
// Serve(net.Listener)，不再代管监听器，也不再有 Shutdown 语义不明的
// runnergroup——因此这里既不调用库的关闭方法，也不需要靠"一次真实 SOCKS5 问候
// 收到应答"来证明 accept 循环已启动（那是为绕开 runnergroup 的 Done-before-Wait
// 永久阻塞与 runner 未注册时监听器泄漏而做的探测，见旧版 waitForAccept）。
//
// 与 Close 的竞争由一个互斥量裁决：Close 先跑则本函数拿到的监听器立即释放并
// 正常返回，绝不留下无人释放的端口。因此不需要调用方事先声明"我要启动了"——
// 上一版为此保留的 MarkStarted/started 状态已随生命周期重写一起删除。
func (s *Socks5Server) Start() error {
	s.udp.start()

	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}

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
