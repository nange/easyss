package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nange/easyss/v3/log"
	"golang.org/x/sync/singleflight"
)

// maxUDPExchanges 限制并发代理 UDP 交换的数量。每个交换占有一条 HTTP/2 流、
// 一个 receiveLoop goroutine 和一个 shaper；按（客户端地址，目标）做键意味着：
// 若客户端每个数据报都使用新的临时 UDP 源端口（Go 的 net.Resolver、某些 curl
// 构建），就会在空闲窗口内累积数百个交换。达到上限时，空闲最久的交换被驱逐。
// 直连 UDP 会话采用同一个上限（见 acquireDirect）。
const maxUDPExchanges = 128

// errSocksServerClosed 表示本地代理服务器已关闭：正在创建中的交换/会话由创建者
// 自己回收，调用方只报告这个错误。
var errSocksServerClosed = errors.New("socks5 udp server closed")

// directUDPConn 将直连 UDP socket 与其最近活动时间戳配对，使清理循环能够回收
// 远端已沉默的会话。
type directUDPConn struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano，每次收发数据报时刷新
}

// udpPoolOptions 是 udpPool 的全部外部依赖。Dial/OpenExchange 以函数值注入，
// 使会话池不需要知道隧道（StreamHandler）与前端（Socks5Server）的存在。
type udpPoolOptions struct {
	// Dial 打开直连 UDP socket（直连会话与会话池自身的清理不涉及隧道）。
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
	// DialTimeout 约束一次直连 UDP 拨号。
	DialTimeout time.Duration
	// IdleTimeout 是两张会话表的空闲回收阈值（清理循环与直连读循环共用）。
	IdleTimeout time.Duration
	// OpenExchange 打开一条经隧道的 UDP 交换（由前端绑定 handler 与 method）。
	OpenExchange func(ctx context.Context, target string, firstPayload []byte) (*UDPExchange, error)
}

// udpPool 管理两类 UDP 会话：经隧道的代理交换（exchanges，键为「客户端_目标」）
// 与直连 socket（direct，键为「direct_客户端_目标」）。它由 SOCKS5 UDP 中继与
// DNS 拦截两条路径共用，因此接管了原本散落在 Socks5Server 上的会话表、
// singleflight 去重、数量上限驱逐与空闲回收。
//
// 会话的 I/O 回调（把数据报发回客户端）仍由前端提供：会话池只负责生命周期。
type udpPool struct {
	opts udpPoolOptions

	mu        sync.RWMutex
	exchanges map[string]*UDPExchange
	direct    map[string]*directUDPConn

	// exchangeSF 对相同 (client, target) 键的并发 acquireExchange 调用去重；
	// inflight 记录正在创建中的数量，使交换数量上限能将其计入。
	// directSF 对相同 (client, target) 键的并发直连 UDP 拨号去重。
	exchangeSF singleflight.Group
	directSF   singleflight.Group
	inflight   atomic.Int64

	// closed 报告会话池已关闭；quit 结束清理循环。两者都由 close 设置，
	// 使创建路径与关闭路径的检查与 Socks5Server.Close 保持既有语义。
	closed    atomic.Bool
	quit      chan struct{}
	closeOnce sync.Once
}

func newUDPPool(opts udpPoolOptions) *udpPool {
	return &udpPool{
		opts:      opts,
		exchanges: make(map[string]*UDPExchange),
		direct:    make(map[string]*directUDPConn),
		quit:      make(chan struct{}),
	}
}

// start 启动空闲回收循环。它必须在派发 goroutine 之前同步调用。
func (p *udpPool) start() {
	go p.cleanupLoop()
}

// close 关闭全部会话：先把两张表从 map 中摘除，再在锁外关闭它们。
// Close 会通过 HTTP/2 流冲刷一个 FIN（一次 io.Pipe 写入），可能因传输层背压而
// 阻塞——此时持有 p.mu 会冻结所有 UDP 处理。closeOnce 保证它与 receiveLoop
// 自身的 Close 并发时是安全的。
//
// 正在创建中的交换由创建者自己回收：OpenExchange 返回后它会检查关闭标志，
// 关闭交换并移除工厂条目（参见 acquireExchange）。
func (p *udpPool) close() {
	p.closed.Store(true)
	p.closeOnce.Do(func() { close(p.quit) })

	var exchanges []*UDPExchange
	p.mu.Lock()
	for key, ue := range p.exchanges {
		delete(p.exchanges, key)
		exchanges = append(exchanges, ue)
	}
	for key, dc := range p.direct {
		dc.conn.Close() //nolint:errcheck
		delete(p.direct, key)
	}
	p.mu.Unlock()

	for _, ue := range exchanges {
		ue.Close() //nolint:errcheck
	}
}

// exchangeFor 返回 key 对应的现有代理交换。它是创建路径的快路径查询，
// 也是测试观察会话表状态的唯一入口。
func (p *udpPool) exchangeFor(key string) (*UDPExchange, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ue, ok := p.exchanges[key]
	return ue, ok
}

// acquireExchange 返回 key 对应的现有 UDPExchange，不存在时通过 OpenExchange
// 创建。firstPayload 非空且交换为新创建时，会被合并进引导记录（省去一次 RTT）。
// 若交换已存在，则忽略 firstPayload。若本次调用创建了交换，created 为 true，
// 调用方绝不能为第一个载荷调用 ue.Send（它已在握手中发送）。ctx 约束交换的创建
// 过程（拨号 + TLS + 引导），供需要硬截止时间的调用方使用（例如启动预热）；
// DNS 路径传入 context.Background()，改而依赖自己的响应超时。
//
// 同一 key 的并发创建通过 singleflight 组去重：第一个调用方执行（较慢的）
// OpenExchange，并发等待者阻塞并复用其结果，因此每个 (client, target) 流
// 恰好只有一条 HTTP/2 流和一个 receiveLoop。
func (p *udpPool) acquireExchange(ctx context.Context, key, dst string, firstPayload []byte) (ue *UDPExchange, created bool, err error) {
	if existing, ok := p.exchangeFor(key); ok {
		return existing, false, nil
	}

	// 在创建前强制交换数量上限。其他 key 正在创建中的数量计入上限；本次调用
	// 自身的创建尚未登记（flight 函数在检查之后才递增 inflight），
	// 与 singleflight 之前的语义一致——那时工厂条目也是在检查之后才插入。
	var evicted *UDPExchange
	p.mu.Lock()
	if len(p.exchanges)+int(p.inflight.Load()) >= maxUDPExchanges {
		evicted = p.evictOldestExchangeLocked()
	}
	p.mu.Unlock()
	// 在锁外关闭被驱逐的交换：Close 会通过 HTTP/2 流冲刷一个 FIN（一次 io.Pipe
	// 写入），可能因传输层背压而阻塞——此时持有 p.mu 会冻结所有 UDP 处理。
	// closeOnce 保证它与 receiveLoop 自身的延迟 Close 并发时是安全的。
	if evicted != nil {
		evicted.Close() //nolint:errcheck
	}

	v, err, shared := p.exchangeSF.Do(key, func() (any, error) {
		p.inflight.Add(1)
		defer p.inflight.Add(-1)

		ue, err := p.opts.OpenExchange(ctx, dst, firstPayload)
		if err != nil {
			return nil, err
		}
		// 交换创建过程中服务器已关闭：立即关闭它，使流及其 receiveLoop 不会
		// 泄漏到关闭之后（清理循环已经退出）。
		if p.closed.Load() {
			ue.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}
		return ue, nil
	})
	if err != nil {
		return nil, false, err
	}
	ue = v.(*UDPExchange)
	if p.closed.Load() {
		// 服务器在 flight 结束之后、交换登记之前被关闭。创建者（shared == false）
		// 拥有该交换并必须关闭它（它尚未在 map 中，因此 close 的 map 扫描无法
		// 回收它）；等待者只报告错误。
		if !shared {
			ue.Close() //nolint:errcheck
		}
		return nil, false, errSocksServerClosed
	}
	// 每个调用方（创建者与等待者）登记同一个指针是幂等的，并让等待者
	// 能用它自己的 ue.Send 发送首个载荷，而不会丢失。
	p.mu.Lock()
	p.exchanges[key] = ue
	p.mu.Unlock()
	// created 报告本次调用的 firstPayload 是否被合并进引导记录：只有创建者的
	// 载荷被合并了（shared == false）。
	return ue, !shared, nil
}

// removeExchange 无条件地把 key 从会话表中删除并关闭交换。它服务于
// 「本次调用拥有该交换」的两条路径：发送失败后的立即回收，以及 receiveLoop
// 退出时的收尾。
func (p *udpPool) removeExchange(key string, ue *UDPExchange) {
	p.mu.Lock()
	delete(p.exchanges, key)
	p.mu.Unlock()
	ue.Close() //nolint:errcheck
}

// invalidateExchange 只在会话表条目仍指向 ue 时才删除并关闭它，避免误删并发
// 重建后的新交换（TCP DNS 的一条连接会跨多条查询复用自己的交换，失效后必须
// 让下一次查询重建，而不是命中残留的已关闭交换）。
func (p *udpPool) invalidateExchange(key string, ue *UDPExchange) {
	if ue == nil {
		return
	}
	p.mu.Lock()
	if cur, ok := p.exchanges[key]; ok && cur == ue {
		delete(p.exchanges, key)
	}
	p.mu.Unlock()
	ue.Close() //nolint:errcheck
}

// evictOldestExchangeLocked 选择空闲最久的交换并将其从 map 中移除，把存活交换
// 数量限制在 maxUDPExchanges 以内。被驱逐的交换返回时并未关闭：调用方必须在
// 释放 p.mu 后关闭它，因为 UDPExchange.Close 会通过 HTTP/2 流冲刷一个 FIN
// （一次 io.Pipe 写入），可能因传输层背压而阻塞——此时持有 p.mu 会冻结所有 UDP
// 处理。closeOnce 保证延迟的关闭与 receiveLoop 自身的 Close 并发时是安全的。
func (p *udpPool) evictOldestExchangeLocked() *UDPExchange {
	var oldestKey string
	var oldestTime time.Time
	for k, ue := range p.exchanges {
		last := ue.LastSeen()
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return nil
	}
	log.Debug("[UDP_PROXY] exchange cap reached, evicting oldest idle", "key", oldestKey)
	evicted := p.exchanges[oldestKey]
	delete(p.exchanges, oldestKey)
	return evicted
}

// directFor 返回 key 对应的现有直连 UDP 会话（创建路径的快路径查询）。
func (p *udpPool) directFor(key string) (*directUDPConn, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	dc, ok := p.direct[key]
	return dc, ok
}

// acquireDirect 返回 key 对应的直连 UDP 会话，不存在时创建其 socket。created
// 为 true 时调用方必须为它启动读取循环（会话池不做任何 I/O）。同一 key 的并发
// 创建者通过 singleflight 组去重（镜像代理路径）：第一个调用方拨号，其余调用方
// 等待并复用其结果，因此每个 (client, target) 流恰好只有一个 socket 和一个读取
// 循环。没有去重时，同一流的两个数据报被并发处理，都会错过 map 查询并各自拨号：
// 一个 socket 被孤立（连同其读取 goroutine 一起泄漏，直到读空闲截止时间），
// 而孤立者的清理随后删除了存活的 map 条目，导致该流每隔约 IdleTimeout 就要更换
// 一个新 socket。
func (p *udpPool) acquireDirect(key, dst string) (*directUDPConn, bool, error) {
	if dc, ok := p.directFor(key); ok {
		return dc, false, nil
	}

	v, err, shared := p.directSF.Do(key, func() (any, error) {
		ctx, cancel := context.WithTimeout(context.Background(), p.opts.DialTimeout)
		rc, err := p.opts.Dial(ctx, "udp", dst)
		cancel()
		if err != nil {
			return nil, err
		}

		// 拨号期间服务器已关闭：关闭 socket，使会话及其读取循环不会泄漏到
		// 关闭之后（清理循环已经退出）。
		if p.closed.Load() {
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}

		dc := &directUDPConn{conn: rc}
		dc.lastSeen.Store(time.Now().UnixNano())

		p.mu.Lock()
		if p.closed.Load() {
			// 在与登记相同的锁下重新检查：与拨号竞争的 close 已经执行过它的
			// 扫描，因此之后再插入的条目永远不会被回收（清理循环与读取循环都
			// 拒绝触碰正在关闭的服务器）。
			p.mu.Unlock()
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}
		// 与代理路径一样强制会话数量上限：否则向许多不同直连目标发送 UDP 的
		// 客户端会为每个流创建一个 socket 加一个 goroutine，且只能靠 30 秒的
		// 清理定时器回收。
		var evicted *directUDPConn
		if len(p.direct) >= maxUDPExchanges {
			evicted = p.evictOldestDirectUDPLocked()
		}
		p.direct[key] = dc
		p.mu.Unlock()

		if evicted != nil {
			// 关闭 socket 会使被驱逐会话的读取循环返回，从而按身份移除它自己
			// （已经被删除）的 map 条目。
			evicted.conn.Close() //nolint:errcheck
		}

		return dc, nil
	})
	if err != nil {
		return nil, false, err
	}
	dc := v.(*directUDPConn)
	// 服务器在 flight 结束后被关闭：创建者已经登记了会话，因此 close 的 map
	// 扫描或读取循环自身的退出会回收它；等待者只报告错误。
	if p.closed.Load() {
		return nil, false, errSocksServerClosed
	}
	return dc, !shared, nil
}

// removeDirect 删除 key 对应的直连会话，但仅当条目仍指向 dc 时：过期的读取循环
// 退出时绝不能删除已经在使用新 socket 的 map 条目。
func (p *udpPool) removeDirect(key string, dc *directUDPConn) {
	p.mu.Lock()
	if cur, ok := p.direct[key]; ok && cur == dc {
		delete(p.direct, key)
	}
	p.mu.Unlock()
}

// evictOldestDirectUDPLocked 选择空闲最久的直连 UDP 会话并将其从 map 中移除，
// 把存活会话数量限制在 maxUDPExchanges 以内。调用方必须在释放 p.mu 后关闭
// 返回的 socket：关闭它会解除会话读取循环的阻塞，而读取循环自己会加锁。
func (p *udpPool) evictOldestDirectUDPLocked() *directUDPConn {
	var oldestKey string
	var oldestTime time.Time
	for k, dc := range p.direct {
		last := time.Unix(0, dc.lastSeen.Load())
		if oldestKey == "" || last.Before(oldestTime) {
			oldestKey, oldestTime = k, last
		}
	}
	if oldestKey == "" {
		return nil
	}
	log.Debug("[UDP_DIRECT] session cap reached, evicting oldest idle", "key", oldestKey)
	evicted := p.direct[oldestKey]
	delete(p.direct, oldestKey)
	return evicted
}

// receiveLoop 把交换收到的数据报交给 onData（由前端负责组帧并发回客户端），
// 直到交换失败或被回收。
//
// respTimeout 是代理 DNS 交换的读空闲超时：查询已经发送（Send 会刷新 lastSeen，
// 所以对于不断重试而上游一直沉默的客户端，默认的空闲回收器永远不会触发），
// 因此服务器长时间沉默意味着上游 DNS 没有应答。超时后关闭交换，使流和 goroutine
// 不会堆积；下一个查询会透明地重建它。任何收到的数据报都会重置该定时器。
// respTimeout <= 0 时禁用该机制（非 DNS 的 UDP）。
func (p *udpPool) receiveLoop(ue *UDPExchange, key string, respTimeout time.Duration, onData func([]byte)) {
	var timer *time.Timer
	if respTimeout > 0 {
		timer = time.AfterFunc(respTimeout, func() {
			log.Debug("[UDP_PROXY] dns response timeout, closing exchange", "key", key)
			ue.Close() //nolint:errcheck // closeOnce 使其与并发的 Close 之间保持安全
		})
		defer timer.Stop()
	}
	defer func() {
		p.removeExchange(key, ue)
	}()

	for {
		data, err := ue.Receive()
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Debug("[UDP_PROXY] receive", "err", err)
			}
			return
		}
		if timer != nil {
			timer.Reset(respTimeout)
		}
		if onData != nil {
			onData(data)
		}
	}
}

// cleanupLoop 回收两张会话表中空闲超时的条目。它按固定周期运行，直到会话池关闭。
func (p *udpPool) cleanupLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			var stale []*UDPExchange
			p.mu.Lock()
			for key, ue := range p.exchanges {
				if time.Since(ue.LastSeen()) > p.opts.IdleTimeout {
					log.Debug("[UDP_PROXY] idle cleanup", "key", key)
					delete(p.exchanges, key)
					stale = append(stale, ue)
				}
			}
			// 直连 UDP 会话采用相同的空闲回收：停止响应的远端对端（或已经结束的
			// 数据报流）不应把 socket 及其读取 goroutine 一直占用到读循环自身的
			// 读空闲截止时间触发。
			for key, dc := range p.direct {
				if time.Since(time.Unix(0, dc.lastSeen.Load())) > p.opts.IdleTimeout {
					log.Debug("[UDP_DIRECT] idle cleanup", "key", key)
					dc.conn.Close() //nolint:errcheck
					delete(p.direct, key)
				}
			}
			p.mu.Unlock()
			// 在锁外关闭被驱逐的交换：Close 会通过 HTTP/2 流冲刷一个 FIN（一次
			// io.Pipe 写入），可能因传输层背压而阻塞——此时持有 p.mu 会冻结
			// 所有 UDP 处理。closeOnce 保证它与 receiveLoop 自身的 Close
			// 并发时是安全的。
			for _, ue := range stale {
				ue.Close() //nolint:errcheck
			}
		case <-p.quit:
			return
		}
	}
}
