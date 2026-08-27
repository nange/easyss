package proxy

import (
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"
	easydns "github.com/nange/easyss/v3/client/dns"
	"github.com/nange/easyss/v3/client/router"
	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/shaper"
	"github.com/nange/easyss/v3/transport"
	"github.com/txthinking/socks5"
)

// pipeStream adapts one end of a net.Pipe connection to transport.Stream so
// tests can read/inject encrypted records on the other end.
type pipeStream struct{ conn net.Conn }

func (s *pipeStream) Read(p []byte) (int, error)  { return s.conn.Read(p) }
func (s *pipeStream) Write(p []byte) (int, error) { return s.conn.Write(p) }
func (s *pipeStream) CloseWrite() error {
	if cw, ok := s.conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
func (s *pipeStream) Close() error { return s.conn.Close() }

var _ transport.Stream = (*pipeStream)(nil)

// newSharedDNSExchange builds a UDPExchange over a net.Pipe pair together
// with a server-side record writer used to inject DNS responses. The client
// side (stream) is what the shared receive loop reads from; responses are
// encrypted on the server side with the same session keys.
func newSharedDNSExchange(t *testing.T) (*UDPExchange, *crypto.RecordWriter, net.Conn) {
	t.Helper()
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	endpoint := config.EndpointUDP
	method := protocol.MethodAES256GCM
	salt, err := crypto.GenerateSalt()
	if err != nil {
		t.Fatalf("GenerateSalt: %v", err)
	}
	sk, err := crypto.NewStreamKeys(key, salt, endpoint)
	if err != nil {
		t.Fatalf("NewStreamKeys: %v", err)
	}

	aadC2S := crypto.BuildAAD(endpoint, salt, "c2s", "session", method)
	c2sEnc, c2sCounter, err := sk.Encryptor("c2s", "session", method)
	if err != nil {
		t.Fatalf("c2s encryptor: %v", err)
	}
	aadS2C := crypto.BuildAAD(endpoint, salt, "s2c", "session", method)
	s2cEnc, s2cCounter, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		t.Fatalf("s2c encryptor: %v", err)
	}

	clientSide, serverSide := net.Pipe()
	clientStream := &pipeStream{conn: clientSide}
	ue := &UDPExchange{
		stream: clientStream,
		tx:     shaper.New(crypto.NewRecordWriter(clientStream, c2sEnc, c2sCounter, aadC2S), shaper.Config{}),
		reader: crypto.NewDecryptedReader(clientStream, aadS2C, s2cEnc, s2cCounter),
		target: "8.8.8.8:53",
	}
	ue.lastSeen.Store(time.Now().UnixNano())

	// Independent server-side s2c counter: both the client reader and the
	// server writer start at counter 0, so records written in order decrypt
	// in order.
	s2cEnc2, s2cCounter2, err := sk.Encryptor("s2c", "session", method)
	if err != nil {
		t.Fatalf("server s2c encryptor: %v", err)
	}
	serverTx := crypto.NewRecordWriter(serverSide, s2cEnc2, s2cCounter2, aadS2C)
	return ue, serverTx, serverSide
}

// injectDNSResponse writes one DNS response as a DATAGRAM frame record on the
// server side of the exchange.
func injectDNSResponse(t *testing.T, serverTx *crypto.RecordWriter, msg *dns.Msg) {
	t.Helper()
	packed, err := msg.Pack()
	if err != nil {
		t.Fatalf("pack dns response: %v", err)
	}
	frame := protocol.NewFrameDATAGRAM(packed)
	if err := serverTx.WriteRecord(protocol.EncodeFrames([]protocol.Frame{frame})); err != nil {
		t.Fatalf("write response record: %v", err)
	}
}

// newSharedDNSHarness returns a Socks5Server with the shared-DNS state wired
// up and a fake socks5 server whose UDPConn delivers responses to clients.
func newSharedDNSHarness(t *testing.T) (*Socks5Server, *socks5.Server) {
	t.Helper()
	rt, err := router.New(router.Config{})
	if err != nil {
		t.Fatalf("router.New: %v", err)
	}
	s := &Socks5Server{
		router:         rt,
		dnsCache:       easydns.NewCache(""),
		dnsRespTimeout: testDNSRespTimeout,
		dnsPending:     make(map[uint16]dnsPendingEntry),
		dnsDedup:       make(map[uint64][]uint16),
		udpExch:        make(map[string]*UDPExchange),
		udpInflight:    make(map[string]*udpExchangeFactory),
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen server udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return s, &socks5.Server{UDPConn: pc}
}

// newFakeDNSClient binds a UDP socket acting as a DNS client.
func newFakeDNSClient(t *testing.T) *net.UDPConn {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("listen client udp: %v", err)
	}
	t.Cleanup(func() { pc.Close() })
	return pc
}

// readDNSResponse reads one SOCKS5 UDP datagram on the fake client socket and
// returns the parsed DNS message.
func readDNSResponse(t *testing.T, client *net.UDPConn) *dns.Msg {
	t.Helper()
	buf := make([]byte, 65535)
	if err := client.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("read client datagram: %v", err)
	}
	d, err := socks5.NewDatagramFromBytes(buf[:n])
	if err != nil {
		t.Fatalf("parse datagram: %v", err)
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(d.Data); err != nil {
		t.Fatalf("unpack dns response: %v", err)
	}
	return msg
}

// TestSharedDNSExchangeRoutesResponsesByRewrittenID verifies that responses
// on the shared stream are routed back to the originating client by the
// rewritten transaction ID, even when two clients used the same original ID.
func TestSharedDNSExchangeRoutesResponsesByRewrittenID(t *testing.T) {
	srv, fakeSocks := newSharedDNSHarness(t)
	ue, serverTx, serverSide := newSharedDNSExchange(t)

	key := "dns_8.8.8.8:53"
	srv.udpExch[key] = ue

	clientA := newFakeDNSClient(t)
	clientB := newFakeDNSClient(t)

	// Two clients with the SAME original ID must not collide on the shared
	// stream: the rewritten IDs differ, so each response goes to its own
	// client with its own original ID restored.
	ridA := srv.allocDNSID()
	ridB := srv.allocDNSID()
	if ridA == ridB {
		t.Fatal("allocated IDs must be distinct")
	}
	srv.dnsPendingMu.Lock()
	srv.dnsPending[ridA] = dnsPendingEntry{origID: 111, client: clientA.LocalAddr().(*net.UDPAddr), hash: 1, deadline: time.Now().Add(time.Minute)}
	srv.dnsPending[ridB] = dnsPendingEntry{origID: 111, client: clientB.LocalAddr().(*net.UDPAddr), hash: 2, deadline: time.Now().Add(time.Minute)}
	srv.dnsPendingMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.receiveLoopSharedDNS(ue, fakeSocks, "8.8.8.8:53", key)
	}()

	respA := &dns.Msg{MsgHdr: dns.MsgHdr{Id: ridA, Response: true}, Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}}}
	injectDNSResponse(t, serverTx, respA)
	respB := &dns.Msg{MsgHdr: dns.MsgHdr{Id: ridB, Response: true}, Question: []dns.Question{{Name: "other.org.", Qtype: dns.TypeA}}}
	injectDNSResponse(t, serverTx, respB)

	gotA := readDNSResponse(t, clientA)
	gotB := readDNSResponse(t, clientB)
	if gotA.Id != 111 || gotB.Id != 111 {
		t.Fatalf("IDs not restored: A=%d B=%d, want 111/111", gotA.Id, gotB.Id)
	}
	if gotA.Question[0].Name != "example.com." || gotB.Question[0].Name != "other.org." {
		t.Fatalf("responses cross-routed: A=%q B=%q", gotA.Question[0].Name, gotB.Question[0].Name)
	}

	// Pending entries must be consumed by routing.
	srv.dnsPendingMu.Lock()
	_, okA := srv.dnsPending[ridA]
	_, okB := srv.dnsPending[ridB]
	srv.dnsPendingMu.Unlock()
	if okA || okB {
		t.Fatal("pending entries must be removed after routing")
	}

	serverSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop did not exit")
	}
}

// TestSharedDNSExchangeDedupFanout verifies that concurrent byte-identical
// queries (differing only in the transaction ID) are answered from a single
// upstream response: the primary client gets its ID restored and the dedup
// waiter gets a clone with its own ID.
func TestSharedDNSExchangeDedupFanout(t *testing.T) {
	srv, fakeSocks := newSharedDNSHarness(t)
	ue, serverTx, serverSide := newSharedDNSExchange(t)

	key := "dns_8.8.8.8:53"
	srv.udpExch[key] = ue

	clientA := newFakeDNSClient(t)
	clientB := newFakeDNSClient(t)

	hash := uint64(42)
	ridA := srv.allocDNSID()
	ridB := srv.allocDNSID()
	srv.dnsPendingMu.Lock()
	srv.dnsPending[ridA] = dnsPendingEntry{origID: 111, client: clientA.LocalAddr().(*net.UDPAddr), hash: hash, deadline: time.Now().Add(time.Minute)}
	srv.dnsPending[ridB] = dnsPendingEntry{origID: 222, client: clientB.LocalAddr().(*net.UDPAddr), hash: hash, deadline: time.Now().Add(time.Minute)}
	srv.dnsPendingMu.Unlock()
	srv.dnsDedupMu.Lock()
	srv.dnsDedup[hash] = []uint16{ridA, ridB}
	srv.dnsDedupMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.receiveLoopSharedDNS(ue, fakeSocks, "8.8.8.8:53", key)
	}()

	resp := &dns.Msg{
		MsgHdr:   dns.MsgHdr{Id: ridA, Response: true},
		Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}},
		Answer: []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.ParseIP("1.2.3.4"),
		}},
	}
	injectDNSResponse(t, serverTx, resp)

	gotA := readDNSResponse(t, clientA)
	gotB := readDNSResponse(t, clientB)
	if gotA.Id != 111 || gotB.Id != 222 {
		t.Fatalf("IDs not restored: A=%d B=%d, want 111/222", gotA.Id, gotB.Id)
	}
	if len(gotA.Answer) != 1 || len(gotB.Answer) != 1 {
		t.Fatalf("cloned response missing answer: A=%d B=%d", len(gotA.Answer), len(gotB.Answer))
	}

	// Both pending entries and the dedup group must be consumed.
	srv.dnsPendingMu.Lock()
	_, okA := srv.dnsPending[ridA]
	_, okB := srv.dnsPending[ridB]
	srv.dnsPendingMu.Unlock()
	if okA || okB {
		t.Fatal("pending entries must be removed after fan-out")
	}
	srv.dnsDedupMu.Lock()
	_, okG := srv.dnsDedup[hash]
	srv.dnsDedupMu.Unlock()
	if okG {
		t.Fatal("dedup group must be removed after fan-out")
	}

	serverSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop did not exit")
	}
}

// TestSharedDNSExchangeDropsUnknownID verifies that a response whose rewritten
// ID was never registered (late response, or the query was swept) is dropped
// instead of being misrouted to a client.
func TestSharedDNSExchangeDropsUnknownID(t *testing.T) {
	srv, fakeSocks := newSharedDNSHarness(t)
	ue, serverTx, serverSide := newSharedDNSExchange(t)

	key := "dns_8.8.8.8:53"
	srv.udpExch[key] = ue
	client := newFakeDNSClient(t)

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.receiveLoopSharedDNS(ue, fakeSocks, "8.8.8.8:53", key)
	}()

	resp := &dns.Msg{MsgHdr: dns.MsgHdr{Id: 9999, Response: true}, Question: []dns.Question{{Name: "example.com.", Qtype: dns.TypeA}}}
	injectDNSResponse(t, serverTx, resp)

	if err := client.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatalf("set read deadline: %v", err)
	}
	buf := make([]byte, 4096)
	if n, _, err := client.ReadFromUDP(buf); err == nil {
		t.Fatalf("unknown-ID response was routed: %d bytes", n)
	}

	serverSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop did not exit")
	}
}

// TestSharedDNSExchangeSilentUpstreamSweepsPendingNotStream verifies that an
// unanswered query (silent upstream DNS) only expires its pending entry and
// never closes the shared stream — one stuck query cannot kill the other
// clients' in-flight queries (unlike the old per-client exchange close).
func TestSharedDNSExchangeSilentUpstreamSweepsPendingNotStream(t *testing.T) {
	srv, fakeSocks := newSharedDNSHarness(t)
	ue, _, serverSide := newSharedDNSExchange(t)

	key := "dns_8.8.8.8:53"
	srv.udpExch[key] = ue
	client := newFakeDNSClient(t)

	// A pending query whose deadline has already passed (upstream silent).
	hash := uint64(7)
	srv.dnsPendingMu.Lock()
	srv.dnsPending[777] = dnsPendingEntry{origID: 111, client: client.LocalAddr().(*net.UDPAddr), hash: hash, deadline: time.Now().Add(-time.Second)}
	srv.dnsPendingMu.Unlock()
	srv.dnsDedupMu.Lock()
	srv.dnsDedup[hash] = []uint16{777}
	srv.dnsDedupMu.Unlock()

	done := make(chan struct{})
	go func() {
		defer close(done)
		srv.receiveLoopSharedDNS(ue, fakeSocks, "8.8.8.8:53", key)
	}()

	// Give the loop a moment to block on the read, then sweep.
	time.Sleep(50 * time.Millisecond)
	srv.sweepDNS()

	srv.dnsPendingMu.Lock()
	_, ok := srv.dnsPending[777]
	srv.dnsPendingMu.Unlock()
	if ok {
		t.Fatal("expired pending entry must be swept")
	}
	srv.dnsDedupMu.Lock()
	_, okG := srv.dnsDedup[hash]
	srv.dnsDedupMu.Unlock()
	if okG {
		t.Fatal("expired dedup group must be swept")
	}

	// The shared stream must NOT be closed by an unanswered query: the
	// exchange stays registered and live.
	if !srv.hasExchange(key) {
		t.Fatal("shared exchange must stay registered after an unanswered query")
	}

	serverSide.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive loop did not exit")
	}
}

// TestProxyDNSQuerySharesOneStreamAndDedups exercises the real proxyDNSQuery
// path: a burst of queries from different clients (and source ports) opens a
// single shared stream, concurrent byte-identical queries are merged, and
// every query is registered with its original ID for response routing.
func TestProxyDNSQuerySharesOneStreamAndDedups(t *testing.T) {
	tr := &mockTransport{streams: []transport.Stream{&mockStream{}}}
	h := newTestStreamHandler(tr)
	srv, err := NewSocks5Server("127.0.0.1:0", "", "", h, nil, "", protocol.MethodAES256GCM, true, 10*time.Second, 30*time.Second, testDNSRespTimeout, nil)
	if err != nil {
		t.Fatalf("NewSocks5Server: %v", err)
	}

	clientA := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40001}
	clientB := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40002}

	q1 := new(dns.Msg)
	q1.SetQuestion("example.com.", dns.TypeA)
	q1.Id = 111
	if err := srv.proxyDNSQuery(nil, clientA, q1, "example.com"); err != nil {
		t.Fatalf("first query: %v", err)
	}
	if got := tr.openCalls(); got != 1 {
		t.Fatalf("first query opened %d streams, want 1", got)
	}

	// An identical query (same bytes except the ID) from another client
	// must neither open a second stream nor trigger a second upstream round
	// trip: it is merged into the primary's dedup group.
	q2 := new(dns.Msg)
	q2.SetQuestion("example.com.", dns.TypeA)
	q2.Id = 222
	if err := srv.proxyDNSQuery(nil, clientB, q2, "example.com"); err != nil {
		t.Fatalf("deduped query: %v", err)
	}
	if got := tr.openCalls(); got != 1 {
		t.Fatalf("deduped query opened %d streams, want 1", got)
	}

	// A different domain reuses the same shared stream (no new open), but
	// forms its own dedup group.
	q3 := new(dns.Msg)
	q3.SetQuestion("other.org.", dns.TypeA)
	q3.Id = 333
	if err := srv.proxyDNSQuery(nil, clientA, q3, "other.org"); err != nil {
		t.Fatalf("third query: %v", err)
	}
	if got := tr.openCalls(); got != 1 {
		t.Fatalf("different domain opened %d streams, want 1 (shared stream)", got)
	}

	// Every query must be registered with its original ID for routing.
	srv.dnsPendingMu.Lock()
	if len(srv.dnsPending) != 3 {
		srv.dnsPendingMu.Unlock()
		t.Fatalf("dnsPending has %d entries, want 3", len(srv.dnsPending))
	}
	var foundA, foundDup bool
	for _, e := range srv.dnsPending {
		if e.origID == 111 {
			foundA = true
		}
		if e.origID == 222 {
			foundDup = true
		}
	}
	srv.dnsPendingMu.Unlock()
	if !foundA || !foundDup {
		t.Fatal("pending entries missing original IDs")
	}

	// Two dedup groups: the duplicate query is grouped with the primary.
	srv.dnsDedupMu.Lock()
	groups := len(srv.dnsDedup)
	var groupSizes []int
	for _, g := range srv.dnsDedup {
		groupSizes = append(groupSizes, len(g))
	}
	srv.dnsDedupMu.Unlock()
	if groups != 2 {
		t.Fatalf("dnsDedup has %d groups, want 2", groups)
	}
	foundSize2 := false
	for _, n := range groupSizes {
		if n == 2 {
			foundSize2 = true
		}
	}
	if !foundSize2 {
		t.Fatalf("expected a dedup group of size 2, got %v", groupSizes)
	}
}

// TestDNSQueryHashIgnoresTransactionID verifies that byte-identical queries
// differing only in their transaction ID hash alike, while queries with
// different questions do not.
func TestDNSQueryHashIgnoresTransactionID(t *testing.T) {
	q1 := new(dns.Msg)
	q1.SetQuestion("example.com.", dns.TypeA)
	q1.Id = 111
	p1, err := q1.Pack()
	if err != nil {
		t.Fatalf("pack q1: %v", err)
	}

	q2 := new(dns.Msg)
	q2.SetQuestion("example.com.", dns.TypeA)
	q2.Id = 222
	p2, err := q2.Pack()
	if err != nil {
		t.Fatalf("pack q2: %v", err)
	}
	if dnsQueryHash(p1) != dnsQueryHash(p2) {
		t.Fatal("identical queries with different IDs must hash alike")
	}

	q3 := new(dns.Msg)
	q3.SetQuestion("other.org.", dns.TypeA)
	p3, err := q3.Pack()
	if err != nil {
		t.Fatalf("pack q3: %v", err)
	}
	if dnsQueryHash(p1) == dnsQueryHash(p3) {
		t.Fatal("different queries must not hash alike")
	}
}
