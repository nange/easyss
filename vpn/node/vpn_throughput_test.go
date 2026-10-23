package vpnnode

import (
	"context"
	"io"
	"net"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"tailscale.com/types/key"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/util/netpipe"
	vpn "github.com/nange/easyss/v3/vpn"
)

// 本文件是"经中继的 VPN 单流吞吐"的可复现基准，默认跳过（EASYSS_VPN_THROUGHPUT_TEST=1
// 才运行）；同进程内连续测多个配置会互相干扰，因此一个进程只测一个配置。
// 实测数字与设计取舍见 docs/architecture.md 要点 19。

// startSource 启动一个尽可能快地写出数据的 TCP 服务（模拟"对端本机的文件服务"）。
func startSource(t *testing.T) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	blob := make([]byte, 64*1024)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close() //nolint:errcheck
				for {
					if _, err := c.Write(blob); err != nil {
						return
					}
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() { _ = ln.Close() }
}

type wanItem struct {
	due time.Time
	b   []byte
}

// wanConn 是长肥管道链路：写入立即进入队列并按单程延迟投递，带宽不限。
// 这模拟的是"隧道 + 公网"这一段：它只贡献延迟与缓冲，不贡献带宽上限。
type wanConn struct {
	net.Conn
	d time.Duration

	rmu   sync.Mutex
	rcond *sync.Cond
	rq    []wanItem
	rerr  error

	wmu sync.Mutex
	wq  []wanItem
	wcv *sync.Cond
}

func newWanConn(c net.Conn, d time.Duration) *wanConn {
	w := &wanConn{Conn: c, d: d}
	w.rcond = sync.NewCond(&w.rmu)
	w.wcv = sync.NewCond(&w.wmu)
	go w.readLoop()
	go w.writeLoop()
	return w
}

func (w *wanConn) readLoop() {
	buf := make([]byte, 64*1024)
	for {
		n, err := w.Conn.Read(buf)
		if n > 0 {
			b := make([]byte, n)
			copy(b, buf[:n])
			w.rmu.Lock()
			w.rq = append(w.rq, wanItem{due: time.Now().Add(w.d), b: b})
			w.rcond.Broadcast()
			w.rmu.Unlock()
		}
		if err != nil {
			w.rmu.Lock()
			w.rerr = err
			w.rcond.Broadcast()
			w.rmu.Unlock()
			return
		}
	}
}

func (w *wanConn) writeLoop() {
	for {
		w.wmu.Lock()
		for len(w.wq) == 0 {
			w.wcv.Wait()
		}
		item := w.wq[0]
		w.wq = w.wq[1:]
		w.wmu.Unlock()

		if wait := time.Until(item.due); wait > 0 {
			time.Sleep(wait)
		}
		if _, err := w.Conn.Write(item.b); err != nil {
			return
		}
	}
}

func (w *wanConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	w.wmu.Lock()
	w.wq = append(w.wq, wanItem{due: time.Now().Add(w.d), b: b})
	w.wcv.Signal()
	w.wmu.Unlock()
	return len(p), nil
}

func (w *wanConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for {
		if len(w.rq) > 0 {
			if wait := time.Until(w.rq[0].due); wait > 0 {
				w.rmu.Unlock()
				time.Sleep(wait)
				w.rmu.Lock()
				continue
			}
			n := copy(p, w.rq[0].b)
			if n < len(w.rq[0].b) {
				w.rq[0].b = w.rq[0].b[n:]
			} else {
				w.rq = w.rq[1:]
			}
			return n, nil
		}
		if w.rerr != nil {
			return 0, w.rerr
		}
		w.rcond.Wait()
	}
}

type dialerFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// wanDialer 让 DERP 连接经过普通 TCP 套接字 + 模拟延迟：内核套接字缓冲是这条路径的
// 天然缓冲，因此它代表"tailscale 设计时假设的形态"。
func wanDialer(d time.Duration) dialerFunc {
	base := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := base.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return newWanConn(c, d), nil
	}
}

// netPipeDialer 让 DERP 连接多一层**无缓冲** net.Pipe：写方必须等中继 goroutine
// 读走，而中继 goroutine 会在隧道写阻塞时停住。
func netPipeDialer(d time.Duration) dialerFunc {
	inner := wanDialer(d)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		wan, err := inner(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		local, remote := net.Pipe()
		go func() {
			go func() {
				_, _ = io.Copy(wan, remote)
				_ = wan.Close()
			}()
			_, _ = io.Copy(remote, wan)
			_ = remote.Close()
		}()
		return local, nil
	}
}

// netpipeDialer 是生产形态：DERP 连接两端是 util/netpipe 的带缓冲内存管道，
// 缓冲取 config.DERPPipeBufferSize（见 runner/derpdialer.go）。
func netpipeDialer(d time.Duration) dialerFunc {
	inner := wanDialer(d)
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		wan, err := inner(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		local, remote := netpipe.Pipe(config.DERPPipeBufferSize)
		go func() {
			go func() {
				_, _ = io.Copy(wan, remote)
				_ = wan.Close()
			}()
			_, _ = io.Copy(remote, wan)
			_ = remote.Close()
		}()
		return local, nil
	}
}

type vpnFixture struct {
	route    *Route
	srcPort  string
	stopSrc  func()
	stopFace func()
}

// newVPNFixtureWithDepth 按生产路径组装一端：进程内 DERP 中继 + 对端面（被访问方）
// + 访问侧。depth 是中继的每客户端待发队列深度（0 = 共享配置的生效默认值）。
func newVPNFixtureWithDepth(t *testing.T, oneWay time.Duration, derpOnly bool, tag string,
	depth int, makeDialer func(time.Duration) dialerFunc) *vpnFixture {
	t.Helper()

	srcAddr, stopSrc := startSource(t)
	_, srcPort, err := net.SplitHostPort(srcAddr)
	if err != nil {
		t.Fatal(err)
	}

	region := startTestDERPWithDepth(t, depth)
	clientKey, err := vpn.LoadOrCreateKey(peerTestPath(t, tag+"-client.key"))
	if err != nil {
		t.Fatalf("LoadOrCreateKey: %v", err)
	}
	identity, err := LoadOrCreateNodeIdentity(peerTestPath(t, tag+"-node-identity.json"))
	if err != nil {
		t.Fatalf("LoadOrCreateNodeIdentity: %v", err)
	}

	dialer := makeDialer(oneWay)
	face := newTestPeerFaceWithOptions(t, PeerFaceOptions{
		Identity:     identity,
		Region:       region,
		PeerPort:     peerTestPort(t),
		AllowClients: []key.NodePublic{clientKey.Public()},
		DERPDialer:   dialer,
		DERPOnly:     derpOnly,
	})
	if err := face.Start(context.Background()); err != nil {
		t.Fatalf("PeerFace.Start: %v", err)
	}

	route, _ := newAccessSideWith(t, face, clientKey, nil,
		ClientSetOptions{DERPOnly: derpOnly, DERPDialer: dialer})

	return &vpnFixture{
		route:    route,
		srcPort:  srcPort,
		stopSrc:  stopSrc,
		stopFace: func() { stopFaceBounded(t, face) },
	}
}

// stopFaceBounded 有界地拆除对端面：tailcat → wireguard-go → magicsock 的关闭路径
// 有会永久阻塞的分支，生产路径也是超时即放弃（见 runner/vpn.go 的 vpnCloseTimeout）。
// 基准里放弃等待只留一个卡住的 goroutine，同步等待会让整个测试超时。
func stopFaceBounded(t *testing.T, face *PeerFace) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		_ = face.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Log("peer face teardown did not finish (known stuck tailcat/gVisor stack); abandoning it")
	}
}

func (f *vpnFixture) dial(t *testing.T, n int) []net.Conn {
	t.Helper()
	conns := make([]net.Conn, 0, n)
	for i := range n {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		conn, err := f.route.DialTCP(ctx, net.JoinHostPort("b", f.srcPort))
		cancel()
		if err != nil {
			t.Fatalf("DialTCP %d: %v", i, err)
		}
		conns = append(conns, conn)
	}
	return conns
}

// measureTransfers 连续建立 n 条**新的**内层连接，每条在 deadline 内尽量读 limit
// 字节，返回每次速率的中位数（KB/s）与最慢一次。
// 不用长连接测稳态：该路径会随机进入 RTO 退避，长连接样本主要反映停顿（见 docs/architecture.md 要点 19）。
func measureTransfers(t *testing.T, f *vpnFixture, n int, limit int, deadline time.Duration) (medianKBps, worstKBps float64) {
	t.Helper()
	rates := make([]float64, 0, n)
	for range n {
		conns := f.dial(t, 1)
		conn := conns[0]
		start := time.Now()
		_ = conn.SetReadDeadline(time.Now().Add(deadline))
		buf := make([]byte, 64*1024)
		got := 0
		for got < limit {
			n, err := conn.Read(buf)
			got += n
			if err != nil {
				break
			}
		}
		elapsed := time.Since(start)
		_ = conn.Close()
		if got == 0 {
			rates = append(rates, 0)
			continue
		}
		rates = append(rates, float64(got)/elapsed.Seconds()/1024)
	}

	sorted := append([]float64(nil), rates...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	if len(sorted)%2 == 0 {
		median = (sorted[len(sorted)/2-1] + sorted[len(sorted)/2]) / 2
	}
	t.Logf("transfers (1MB each): %v → median %.0f KB/s, worst %.0f KB/s",
		func() []int {
			out := make([]int, len(rates))
			for i, r := range rates {
				out[i] = int(r)
			}
			return out
		}(), median, sorted[0])
	return median, sorted[0]
}

// vpnThroughputTestEnv 是本基准的开关：吞吐断言在任意 CI 机器上都易碎，因此默认跳过。
const vpnThroughputTestEnv = "EASYSS_VPN_THROUGHPUT_TEST"

// TestVPNRelayThroughputBaseline 度量经中继的单流吞吐，并给出保守下限。
// 下限远低于实测，只用于抓**量级回退**（换回无缓冲 net.Pipe 或把队列深度调回 32
// 都会当场失败）；实测数字见 docs/architecture.md 要点 19。
func TestVPNRelayThroughputBaseline(t *testing.T) {
	if os.Getenv(vpnThroughputTestEnv) == "" {
		t.Skipf("set %s=1 to run the relayed-throughput baseline (see this file's header)", vpnThroughputTestEnv)
	}

	owMS := 60
	if v := os.Getenv("EASYSS_VPN_TPUT_OW_MS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("EASYSS_VPN_TPUT_OW_MS = %q, want a positive integer", v)
		}
		owMS = n
	}
	depth := 0
	if v := os.Getenv("EASYSS_VPN_TPUT_DEPTH"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("EASYSS_VPN_TPUT_DEPTH = %q, want a positive integer", v)
		}
		depth = n
	}

	shape := os.Getenv("EASYSS_VPN_TPUT_SHAPE")
	if shape == "" {
		shape = "bufpipe"
	}
	shapes := map[string]struct {
		makeDialer func(time.Duration) dialerFunc
		derpOnly   bool
		floorKBps  float64
	}{
		// 直连对照：不经中继时 WireGuard + netstack 本身不慢（本机 loopback）。
		"direct": {wanDialer, false, 5_000},
		// tailscale 设计时假设的形态：DERP 连接是真实 TCP 套接字（有内核缓冲）。
		"tcp": {wanDialer, true, 200},
		// 无缓冲 net.Pipe 形态，仅用于 A/B 对照。
		"netpipe": {netPipeDialer, true, 100},
		// 生产形态：util/netpipe 的带缓冲内存管道 + 共享配置里的固定缓冲。
		"bufpipe": {netpipeDialer, true, 200},
	}
	tc, ok := shapes[shape]
	if !ok {
		t.Fatalf("unknown EASYSS_VPN_TPUT_SHAPE %q (want direct, tcp, netpipe or bufpipe)", shape)
	}
	// 下限随队列深度缩放：显式配一个很小的队列本来就会压低吞吐，那不是回归。
	floor := tc.floorKBps
	if depth > 0 && depth < 8*config.MinDERPSendQueueDepth {
		floor = min(floor, 80)
	}

	oneWay := time.Duration(owMS) * time.Millisecond
	f := newVPNFixtureWithDepth(t, oneWay, tc.derpOnly, shape, depth, tc.makeDialer)
	defer f.stopSrc()
	defer f.stopFace()

	medianKBps, worstKBps := measureTransfers(t, f, 5, 1<<20, 15*time.Second)
	t.Logf("shape=%s depth=%d ow=%dms → median %.0f KB/s (worst %.0f KB/s)",
		shape, depth, owMS, medianKBps, worstKBps)
	if medianKBps < floor {
		t.Errorf("%s: median %.0f KB/s is below the %.0f KB/s floor (see the baselines in this file's header)",
			shape, medianKBps, floor)
	}
}
