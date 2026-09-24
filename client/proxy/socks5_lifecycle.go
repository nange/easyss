package proxy

import (
	"errors"
	"io"
	"net"
	"time"

	"github.com/nange/easyss/v3/log"
)

// MarkStarted 记录 Start 即将被调用。它必须在以 goroutine 方式启动 Start 之前
// 同步调用：若在 Start 内部设置该标志，在单核调度器上会与 Close 竞争，
// 导致服务器 goroutine 泄漏其监听器。
func (s *Socks5Server) MarkStarted() {
	s.started.Store(true)
}

func (s *Socks5Server) Start() error {
	s.started.Store(true)
	s.udp.start()
	return s.srv.ListenAndServe(s)
}

// acceptProbeTimeout 限制 waitForAccept 等待 accept 循环就绪的时长。它只在
// "启动 socks5 服务器后紧接着关闭"这一路径上被消耗：服务器已经在运行时第一次
// 探测就会成功，等待时间约等于零。CI 上出现过 accept 循环在一台超载的
// windows-arm64 runner 上迟迟不响应的实例，因此预算给得比一次调度延迟宽松。
const acceptProbeTimeout = 3 * time.Second

// acceptProbeInterval 是同步探测两次尝试之间的间隔。
const acceptProbeInterval = 20 * time.Millisecond

// acceptShutdownGrace 是 Close 放弃同步等待后，后台补关闭继续等待 accept 循环
// 就绪的上限。预算给得很宽：补关闭只在"启动后立刻关闭"这条路径上被用到，慢一点
// 没有代价，但把迟到数秒的 accept 循环留在后台会永久占住一个本地端口——CI 上
// 出现过 3s 预算内探测不到应答的实例，那是调度延迟而不是真的没启动。
const acceptShutdownGrace = 30 * time.Second

// acceptShutdownProbeInterval 是后台补关闭两次探测之间的间隔：它比同步探测宽松
// 得多，因为这条路径上没有任何调用方在等它。
const acceptShutdownProbeInterval = 200 * time.Millisecond

// errAcceptNotReady 在 accept 循环迟迟未就绪时由 Close 返回：Close 没有同步等待
// 库的 Shutdown（见 shutdown），监听地址与已接受的连接改由后台补关闭在 accept
// 循环就绪后释放。
var errAcceptNotReady = errors.New("socks5 server accept loop did not start in time; shutdown deferred")

// waitForAccept 报告 accept 循环是否在同步预算内被证实已启动。
func (s *Socks5Server) waitForAccept() bool {
	return s.waitForAcceptWithin(acceptProbeTimeout)
}

// waitForAcceptWithin 轮询监听地址，直到服务器真正开始接受连接，报告 accept
// 循环是否在预算内就绪。单纯的 TCP 拨号不够：只要监听器在内核层面完成绑定它
// 就会成功，而此时 txthinking/socks5 runnergroup 库内部的 accept 循环尚未注册
// 其 runner。在这个窗口内调用 Shutdown 要么泄漏监听器（尚未添加任何 runner 时
// runnergroup.Done 会提前返回），要么死锁（Done 会跳过启动 goroutine 尚未运行的
// runner，然后永远阻塞等待一个永远不会到来的完成信号）。只有用真实的 SOCKS5
// 问候并收到回复来探测，才能证明 accept 循环已经运行：探测成功意味着 runner
// 早已被调度过，因此调用方永远不会与 Start 派生的 goroutine 竞争。
func (s *Socks5Server) waitForAcceptWithin(timeout time.Duration) bool {
	if s.srv == nil {
		return false
	}
	addr := s.srv.Addr
	if addr == "" {
		return false
	}
	// SOCKS5 问候：版本 5，提供一个方法，无认证。只有 accept 循环接受了
	// 我们的连接并解析完问候后，服务器才会应答。
	greeting := []byte{0x05, 0x01, 0x00}
	deadline := time.Now().Add(timeout)
	for {
		if probeSocks5Accept(addr, greeting) {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(acceptProbeInterval)
	}
}

// probeSocks5Accept 拨号 addr 并执行一次 SOCKS5 协商。它报告服务器是否接受了
// 连接并应答了问候，以此证明 accept 循环已启动并完成注册。
func probeSocks5Accept(addr string, greeting []byte) bool {
	c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
	if err != nil {
		return false
	}
	defer c.Close() //nolint:errcheck
	if err := c.SetDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		return false
	}
	if _, err := c.Write(greeting); err != nil {
		return false
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(c, reply); err != nil {
		return false
	}
	return reply[0] == 0x05
}

func (s *Socks5Server) Close() error {
	// 关闭全部 UDP 会话（代理交换与直连 socket）。正在创建中的交换由创建者
	// 自己回收：OpenExchange 返回后它会检查关闭标志，关闭交换并移除工厂条目
	// （参见 udpPool.acquireExchange）。
	if s.udp != nil {
		s.udp.close()
	}
	return s.shutdown()
}

// shutdown 关闭库级服务器，并且绝不为了等一个不会到来的信号而挂住调用方。
//
// 库的 Shutdown 就是 runnergroup.Done：在 Wait 尚未进入时它会永久阻塞在
// <-g.done 上（2026-09-17 的 windows-arm64 CI 正是这样把整个 job 拖到 30 分钟
// 超时）。一次真实的 SOCKS5 问候得到应答才能证明 accept 循环已在跑，也就证明
// Wait 已进入、Done 必定有界。因此探测成功就同步 Shutdown 并把库的结果交给调用
// 方；探测失败立即返回 errAcceptNotReady，把补关闭交给后台（见 deferredShutdown）
// ——调用方不阻塞，迟到数秒的 accept 循环也不会永久占着本地端口。
func (s *Socks5Server) shutdown() error {
	if s.srv == nil {
		return nil
	}
	// 没有经过 MarkStarted/Start 就直接 Close：RunGroup 里还没有 runner，Done
	// 不会阻塞也不会死锁（MarkStarted 的契约就是"必须在派发 Start 之前调用"），
	// 直接走库的 Shutdown 保持原语义。
	if !s.started.Load() {
		return s.srv.Shutdown()
	}
	if s.waitForAccept() {
		return s.srv.Shutdown()
	}
	log.Error("[SOCKS5] accept loop not ready, shutdown deferred",
		"addr", s.srv.Addr, "timeout", acceptProbeTimeout, "grace", acceptShutdownGrace)
	go s.deferredShutdown()
	return errAcceptNotReady
}

// deferredShutdown 是 shutdown 的后台补关闭。它只在 accept 循环被证实已启动后
// 才调用库的 Shutdown，因此永远不会踩到 Done-before-Wait 的死锁；宽限期用尽仍
// 未就绪时放弃：此时库的 ListenAndServe 早已从它自己的错误路径返回（那条路径会
// 关掉 TCP 监听），没有监听器需要释放。
func (s *Socks5Server) deferredShutdown() {
	deadline := time.Now().Add(acceptShutdownGrace)
	for time.Now().Before(deadline) {
		if !s.waitForAcceptWithin(acceptShutdownProbeInterval) {
			continue
		}
		if err := s.srv.Shutdown(); err != nil {
			log.Error("[SOCKS5] deferred shutdown failed", "addr", s.srv.Addr, "err", err)
			return
		}
		log.Info("[SOCKS5] accept loop answered late, deferred shutdown done", "addr", s.srv.Addr)
		return
	}
	log.Error("[SOCKS5] accept loop never answered, deferred shutdown gave up", "addr", s.srv.Addr)
}
