package proxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// 模拟外层 exchangeFor 与 flight 之间的窗口内已有条目：进入 flight 后必须重查并直接
// 复用，不能再跑 OpenExchange——首载荷会写进一条马上被丢弃的引导记录，调用方随后还会
// 在复用的交换上再发一次。
func TestCreateExchangeReusesRegisteredEntry(t *testing.T) {
	existingStream := newBlockingStream()
	existing := &UDPExchange{stream: existingStream}
	var opens atomic.Int32
	p := newUDPPool(udpPoolOptions{
		OpenExchange: func(context.Context, string, []byte) (*UDPExchange, error) {
			opens.Add(1)
			return &UDPExchange{stream: newBlockingStream()}, nil
		},
	})
	p.exchanges["client_target"] = existing

	creation, err := p.createExchange(context.Background(), "client_target", "target:53", []byte("q"), new(int))
	if err != nil {
		t.Fatalf("createExchange: %v", err)
	}
	if creation.ue != existing {
		t.Fatalf("returned %p, want the already registered exchange %p", creation.ue, existing)
	}
	if creation.created {
		t.Fatal("reusing an existing exchange must not report created")
	}
	if got := opens.Load(); got != 0 {
		t.Fatalf("OpenExchange calls = %d, want 0", got)
	}
	if existingStream.isClosed() {
		t.Fatal("the reused exchange must stay open")
	}
}

// flight 内重查命中的复用者与本次创建者持有同一个 token；经 flight 路径覆盖
// (created=false, owner==token)。若归属判定只看 owner，调用方会跳过 Send 并多起一个
// receiveLoop。入口快路径会遮蔽复用分支，所以这里直接走 acquireExchangeFlight。
func TestAcquireExchangeFlightReuseIsNotCreated(t *testing.T) {
	existingStream := newBlockingStream()
	existing := &UDPExchange{stream: existingStream}
	var opens atomic.Int32
	p := newUDPPool(udpPoolOptions{
		OpenExchange: func(context.Context, string, []byte) (*UDPExchange, error) {
			opens.Add(1)
			return &UDPExchange{stream: newBlockingStream()}, nil
		},
	})
	p.exchanges["client_target"] = existing

	ue, created, err := p.acquireExchangeFlight(context.Background(), "client_target", "target:53", []byte("q"))
	if err != nil {
		t.Fatalf("acquireExchangeFlight: %v", err)
	}
	if ue != existing {
		t.Fatalf("returned %p, want the already registered exchange %p", ue, existing)
	}
	if created {
		t.Fatal("a caller reusing a registered exchange must not report created")
	}
	if got := opens.Load(); got != 0 {
		t.Fatalf("OpenExchange calls = %d, want 0", got)
	}
	if existingStream.isClosed() {
		t.Fatal("the reused exchange must stay open")
	}
}

// 入口重查之后同 key 的 flight 串行，正常流程不会再插入条目；这里防御的是将来新增的
// 写点。若真的出现条目，覆盖会让旧交换失去回收者，复用则意味着首个载荷已经在即将
// 丢弃的流上发过一遍；两者都不能做，关掉新交换并报错。
func TestCreateExchangeRefusesRegistrationDuringFlight(t *testing.T) {
	existingStream := newBlockingStream()
	existing := &UDPExchange{stream: existingStream}
	freshStream := newBlockingStream()

	p := newUDPPool(udpPoolOptions{})
	p.opts.OpenExchange = func(context.Context, string, []byte) (*UDPExchange, error) {
		p.mu.Lock()
		p.exchanges["client_target"] = existing
		p.mu.Unlock()
		return &UDPExchange{stream: freshStream}, nil
	}

	_, err := p.createExchange(context.Background(), "client_target", "target:53", []byte("q"), new(int))
	if err == nil {
		t.Fatal("createExchange must refuse a registration that appeared during OpenExchange")
	}
	if got := p.exchanges["client_target"]; got != existing {
		t.Fatalf("registered exchange = %p, want %p", got, existing)
	}
	if !freshStream.isClosed() {
		t.Fatal("the freshly opened duplicate must be closed")
	}
	if existingStream.isClosed() {
		t.Fatal("the already registered exchange must stay open")
	}
}

// singleflight 合并创建时只能有一个调用者拿到 created=true（由它启动 receiveLoop）；
// 等待者共享同一个交换。singleflight 的 shared 对执行者也可能是 true，不能用它判断。
func TestAcquireExchangeSharedFlightCreatesOnce(t *testing.T) {
	var opens atomic.Int32
	p := newUDPPool(udpPoolOptions{
		OpenExchange: func(context.Context, string, []byte) (*UDPExchange, error) {
			opens.Add(1)
			time.Sleep(100 * time.Millisecond)
			return &UDPExchange{stream: newBlockingStream()}, nil
		},
	})

	const callers = 16
	start := make(chan struct{})
	results := make(chan *UDPExchange, callers)
	var createdCount atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			ue, created, err := p.acquireExchange(context.Background(), "client_target", "target:53", []byte("q"))
			if err != nil {
				t.Errorf("acquireExchange: %v", err)
				return
			}
			if created {
				createdCount.Add(1)
			}
			results <- ue
		})
	}
	close(start)
	wg.Wait()
	close(results)

	if got := opens.Load(); got != 1 {
		t.Fatalf("OpenExchange calls = %d, want 1", got)
	}
	if got := createdCount.Load(); got != 1 {
		t.Fatalf("created callers = %d, want exactly 1", got)
	}
	var first *UDPExchange
	for ue := range results {
		if first == nil {
			first = ue
			continue
		}
		if ue != first {
			t.Fatalf("callers got different exchanges: %p and %p", ue, first)
		}
	}
	p.close()
}

func TestAcquireExchangeRefusesAfterClose(t *testing.T) {
	stream := newBlockingStream()
	p := newUDPPool(udpPoolOptions{
		OpenExchange: func(context.Context, string, []byte) (*UDPExchange, error) {
			return &UDPExchange{stream: stream}, nil
		},
	})
	p.close()

	if _, _, err := p.acquireExchange(context.Background(), "client_target", "target:53", nil); !errors.Is(err, errSocksServerClosed) {
		t.Fatalf("acquireExchange error = %v, want errSocksServerClosed", err)
	}
	if !stream.isClosed() {
		t.Fatal("an exchange opened after close must be closed")
	}
}

// trackedConn 只用于断言池是否关闭了某条 socket。
type trackedConn struct{ closed atomic.Bool }

func (c *trackedConn) Read([]byte) (int, error)    { return 0, io.EOF }
func (c *trackedConn) Write(p []byte) (int, error) { return len(p), nil }
func (c *trackedConn) Close() error {
	c.closed.Store(true)
	return nil
}
func (c *trackedConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *trackedConn) RemoteAddr() net.Addr             { return &net.UDPAddr{} }
func (c *trackedConn) SetDeadline(time.Time) error      { return nil }
func (c *trackedConn) SetReadDeadline(time.Time) error  { return nil }
func (c *trackedConn) SetWriteDeadline(time.Time) error { return nil }

// 直连路径与 exchange 路径有同一个登记窗口：后到的 flight 不能覆盖已登记的 socket，
// 否则旧 socket 的读循环（现已无 deadline）会永久泄漏。
func TestAcquireDirectKeepsExistingRegistration(t *testing.T) {
	existingStream := &trackedConn{}
	existing := &directUDPConn{conn: existingStream}
	freshStream := &trackedConn{}

	p := newUDPPool(udpPoolOptions{})
	p.opts.Dial = func(context.Context, string, string) (net.Conn, error) {
		p.mu.Lock()
		p.direct["direct_key"] = existing
		p.mu.Unlock()
		return freshStream, nil
	}

	dc, created, err := p.acquireDirect("direct_key", "target:53")
	if err != nil {
		t.Fatalf("acquireDirect: %v", err)
	}
	if dc != existing {
		t.Fatalf("returned %p, want the already registered direct conn %p", dc, existing)
	}
	if created {
		t.Fatal("reusing an existing direct conn must not report created")
	}
	if got := p.direct["direct_key"]; got != existing {
		t.Fatalf("registered direct conn = %p, want %p", got, existing)
	}
	if !freshStream.closed.Load() {
		t.Fatal("the freshly dialed duplicate socket must be closed")
	}
	if existingStream.closed.Load() {
		t.Fatal("the reused direct conn must stay open")
	}
}

// singleflight 合并时只能有一个调用者拿到 created=true（由它启动读循环）。
func TestAcquireDirectSharedFlightCreatesOnce(t *testing.T) {
	var dials atomic.Int32
	p := newUDPPool(udpPoolOptions{
		Dial: func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			time.Sleep(100 * time.Millisecond)
			return &trackedConn{}, nil
		},
	})

	const callers = 16
	start := make(chan struct{})
	results := make(chan *directUDPConn, callers)
	var createdCount atomic.Int32
	var wg sync.WaitGroup
	for range callers {
		wg.Go(func() {
			<-start
			dc, created, err := p.acquireDirect("direct_key", "target:53")
			if err != nil {
				t.Errorf("acquireDirect: %v", err)
				return
			}
			if created {
				createdCount.Add(1)
			}
			results <- dc
		})
	}
	close(start)
	wg.Wait()
	close(results)

	if got := dials.Load(); got != 1 {
		t.Fatalf("Dial calls = %d, want 1", got)
	}
	if got := createdCount.Load(); got != 1 {
		t.Fatalf("created callers = %d, want exactly 1", got)
	}
	var first *directUDPConn
	for dc := range results {
		if first == nil {
			first = dc
			continue
		}
		if dc != first {
			t.Fatalf("callers got different direct conns: %p and %p", dc, first)
		}
	}
	p.close()
}

// TestRemoveExchangeKeepsReplacement 固定"过期的 receiveLoop 收尾不得删掉
// 新交换"：驱逐/空闲清理摘除旧交换后，同一 key 可能已经登记了替代者；旧
// receiveLoop 的 defer 若无条件 delete，会把替代者从池里抹掉，留下一个无人
// 回收的交换（非 DNS 的 UDP 交换没有读空闲定时器）。
func TestRemoveExchangeKeepsReplacement(t *testing.T) {
	p := newUDPPool(udpPoolOptions{})

	oldStream := newBlockingStream()
	old := &UDPExchange{stream: oldStream}
	replacementStream := newBlockingStream()
	replacement := &UDPExchange{stream: replacementStream}

	p.exchanges["client_target"] = replacement
	p.removeExchange("client_target", old)

	if got := p.exchanges["client_target"]; got != replacement {
		t.Fatalf("replacement exchange was removed from the pool: got %p, want %p", got, replacement)
	}
	if !oldStream.isClosed() {
		t.Fatal("the removed exchange must still be closed")
	}
	if replacementStream.isClosed() {
		t.Fatal("the replacement exchange must not be closed")
	}
}

// TestAddUDPRelayRefusesAfterClose 固定“Close 扫描过表之后不再接受新中继”：
// 否则在扫描与登记之间插入的 socket 不会被任何一方关闭。
func TestAddUDPRelayRefusesAfterClose(t *testing.T) {
	s := &Socks5Server{}
	s.closeUDPRelays()

	if s.addUDPRelay(&udpRelay{}) {
		t.Fatal("relay registration must be refused after the server is closed")
	}
}

// TestRemoveExchangeDeletesOwnEntry 覆盖正常收尾：条目仍指向本交换时删除。
func TestRemoveExchangeDeletesOwnEntry(t *testing.T) {
	p := newUDPPool(udpPoolOptions{})
	stream := newBlockingStream()
	ue := &UDPExchange{stream: stream}
	p.exchanges["client_target"] = ue

	p.removeExchange("client_target", ue)

	if _, ok := p.exchanges["client_target"]; ok {
		t.Fatal("the owning exchange should be removed from the pool")
	}
	if !stream.isClosed() {
		t.Fatal("the removed exchange must be closed")
	}
}
