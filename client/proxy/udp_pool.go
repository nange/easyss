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

// maxUDPExchanges 限制并发 UDP 交换数，每个交换占一条流、一个 goroutine 和一个 shaper。
// 键含客户端地址：每数据报换一个源端口的客户端会累积大量交换，达到上限时驱逐空闲最久的。
const maxUDPExchanges = 128

var errSocksServerClosed = errors.New("socks5 udp server closed")

type directUDPConn struct {
	conn     net.Conn
	lastSeen atomic.Int64 // UnixNano，收发数据报时刷新
}

type udpPoolOptions struct {
	Dial         func(ctx context.Context, network, addr string) (net.Conn, error)
	DialTimeout  time.Duration
	IdleTimeout  time.Duration
	OpenExchange func(ctx context.Context, target string, firstPayload []byte) (*UDPExchange, error)
}

// udpPool 管理两类 UDP 会话：经隧道的代理交换与直连 socket。会话池只负责生命周期，
// I/O 回调由前端提供。
type udpPool struct {
	opts udpPoolOptions

	mu        sync.RWMutex
	exchanges map[string]*UDPExchange
	direct    map[string]*directUDPConn

	// exchangeSF/directSF 对同键并发创建去重；inflight 让创建中的交换也计入上限。
	exchangeSF singleflight.Group
	directSF   singleflight.Group
	inflight   atomic.Int64

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

func (p *udpPool) start() {
	go p.cleanupLoop()
}

// close 先把两张表从 map 摘除，再在锁外关闭。Close 会冲刷 FIN 并可能因传输层背压阻塞，
// 持有 p.mu 会冻结所有 UDP 处理。
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

func (p *udpPool) exchangeFor(key string) (*UDPExchange, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ue, ok := p.exchanges[key]
	return ue, ok
}

// acquireExchange 返回 key 对应的交换，不存在时用 firstPayload 创建（省去一次 RTT）。
// created 为 true 时调用方不能再为第一个载荷调用 ue.Send。
func (p *udpPool) acquireExchange(ctx context.Context, key, dst string, firstPayload []byte) (ue *UDPExchange, created bool, err error) {
	if existing, ok := p.exchangeFor(key); ok {
		return existing, false, nil
	}

	var evicted *UDPExchange
	p.mu.Lock()
	if len(p.exchanges)+int(p.inflight.Load()) >= maxUDPExchanges {
		evicted = p.evictOldestExchangeLocked()
	}
	p.mu.Unlock()
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
		// 创建期间服务器已关闭：立即关闭，否则流及其 receiveLoop 会泄漏到关闭之后。
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
		// 服务器在 flight 结束之后、交换登记之前被关闭。创建者拥有该交换并必须关闭它
		// （它尚未在 map 中，close 的扫描回收不到）；等待者只报错。
		if !shared {
			ue.Close() //nolint:errcheck
		}
		return nil, false, errSocksServerClosed
	}
	p.mu.Lock()
	p.exchanges[key] = ue
	p.mu.Unlock()
	return ue, !shared, nil
}

// removeExchange 在条目仍指向 ue 时删除并关闭它。必须校验身份：旧 receiveLoop 的 defer
// 会晚一步执行，无条件 delete 会把同 key 的新条目删掉，池从此对这条交换失明。
func (p *udpPool) removeExchange(key string, ue *UDPExchange) {
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

// evictOldestExchangeLocked 移除并返回空闲最久的交换。调用方必须在释放 p.mu 后关闭它：
// Close 可能因传输层背压阻塞。
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

func (p *udpPool) directFor(key string) (*directUDPConn, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	dc, ok := p.direct[key]
	return dc, ok
}

// acquireDirect 返回 key 对应的直连会话，不存在时拨号创建；created 为 true 时调用方必须为它
// 启动读取循环。并发创建经 singleflight 去重，否则两个数据报会各自拨号，多出的 goroutine 泄漏。
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

		if p.closed.Load() {
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}

		dc := &directUDPConn{conn: rc}
		dc.lastSeen.Store(time.Now().UnixNano())

		p.mu.Lock()
		if p.closed.Load() {
			// 在与登记相同的锁下重新检查：与拨号竞争的 close 已执行过扫描，之后再插入
			// 的条目永远不会被回收。
			p.mu.Unlock()
			rc.Close() //nolint:errcheck
			return nil, errSocksServerClosed
		}
		var evicted *directUDPConn
		if len(p.direct) >= maxUDPExchanges {
			evicted = p.evictOldestDirectUDPLocked()
		}
		p.direct[key] = dc
		p.mu.Unlock()

		if evicted != nil {
			evicted.conn.Close() //nolint:errcheck
		}

		return dc, nil
	})
	if err != nil {
		return nil, false, err
	}
	dc := v.(*directUDPConn)
	if p.closed.Load() {
		return nil, false, errSocksServerClosed
	}
	return dc, !shared, nil
}

func (p *udpPool) removeDirect(key string, dc *directUDPConn) {
	p.mu.Lock()
	if cur, ok := p.direct[key]; ok && cur == dc {
		delete(p.direct, key)
	}
	p.mu.Unlock()
}

// evictOldestDirectUDPLocked 移除并返回空闲最久的直连会话。调用方必须在释放 p.mu 后关闭
// socket：关闭会唤醒该会话的读取循环，而读取循环自己会加锁。
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

// receiveLoop 把交换收到的数据报交给 onData。respTimeout 是代理 DNS 交换的读空闲超时：Send
// 会刷新 lastSeen，不断重试而上游沉默的客户端只能靠它关闭，<= 0 表示禁用。
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
			for key, dc := range p.direct {
				if time.Since(time.Unix(0, dc.lastSeen.Load())) > p.opts.IdleTimeout {
					log.Debug("[UDP_DIRECT] idle cleanup", "key", key)
					dc.conn.Close() //nolint:errcheck
					delete(p.direct, key)
				}
			}
			p.mu.Unlock()
			// 在锁外关闭：Close 可能因传输层背压阻塞，持有 p.mu 会冻结所有 UDP 处理。
			for _, ue := range stale {
				ue.Close() //nolint:errcheck
			}
		case <-p.quit:
			return
		}
	}
}
