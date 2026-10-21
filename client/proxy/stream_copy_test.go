package proxy

import (
	"bytes"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
)

// 预读 goroutine 只负责把读与写解耦，记录顺序、FIN/RST 与读错误仍必须按原语义到达本地连接。
func TestCopyRemoteToLocal(t *testing.T) {
	t.Run("preserves data order and stops at FIN", func(t *testing.T) {
		rx := s2cReader(t, [][]protocol.Frame{
			{protocol.NewFrameDATA([]byte("one"))},
			{protocol.NewFramePADDING(16), protocol.NewFrameDATA([]byte("two"))},
			{protocol.NewFrameFIN()},
		}, nil)

		got, err := runRemoteCopy(t, rx)
		require.NoError(t, err)
		require.Equal(t, "onetwo", got)
	})

	t.Run("writes queued data before reporting RST", func(t *testing.T) {
		rx := s2cReader(t, [][]protocol.Frame{
			{protocol.NewFrameDATA([]byte("x"))},
			{protocol.NewFrameRST()},
		}, nil)

		got, err := runRemoteCopy(t, rx)
		require.ErrorIs(t, err, ErrStreamReset)
		require.Equal(t, "x", got)
	})

	t.Run("propagates a read error after queued data", func(t *testing.T) {
		rx := s2cReader(t, [][]protocol.Frame{
			{protocol.NewFrameDATA([]byte("ok"))},
		}, []byte{0, 0, 8, 1, 2}) // 第二条记录声明 8 字节密文却只给 2 字节，读到一半截断。

		got, err := runRemoteCopy(t, rx)
		require.ErrorIs(t, err, io.ErrUnexpectedEOF)
		require.Equal(t, "ok", got)
	})

	// 预读的全部意义：本地写阻塞时仍继续读 body、归还 h2 连接级窗口。同步实现会停在这条写里，
	// 计数不再增长，本用例因此会失败。
	t.Run("keeps reading while the local write is blocked", func(t *testing.T) {
		sk := s2cKeys(t)
		wire := s2cWire(t, sk, [][]protocol.Frame{
			{protocol.NewFrameDATA([]byte("first"))},
			{protocol.NewFrameDATA([]byte("second"))},
			{protocol.NewFrameFIN()},
		}, nil)

		counter := &countingReader{r: bytes.NewReader(wire)}
		rx, err := sk.NewReader(counter, crypto.DirS2C, protocol.MethodAES256GCM)
		require.NoError(t, err)

		conn := newBlockingWriteConn()
		defer conn.unblock()

		m := stats.NewStreamMeter("client", "test")
		defer m.Close()

		result := make(chan error, 1)
		go func() {
			result <- (&StreamHandler{}).copyRemoteToLocal(rx, conn, func() {}, m)
		}()

		select {
		case <-conn.started:
		case <-time.After(2 * time.Second):
			t.Fatal("first local write did not start")
		}

		require.Eventually(t, func() bool {
			return counter.n.Load() == int64(len(wire))
		}, time.Second, 5*time.Millisecond, "prefetch stalled while the local write was blocked")

		select {
		case err := <-result:
			t.Fatalf("copy finished while the first local write was still blocked: %v", err)
		default:
		}

		conn.unblock()
		require.NoError(t, <-result)
	})
}

// s2cKeys 返回一对写入器/读取器共用的会话密钥。
func s2cKeys(t *testing.T) *crypto.StreamKeys {
	t.Helper()

	masterKey, err := crypto.DeriveMasterKey("copy-remote-to-local")
	require.NoError(t, err)
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	sk, err := crypto.NewStreamKeys(masterKey, salt, config.EndpointTCP)
	require.NoError(t, err)
	return sk
}

// s2cWire 把 records 依次编码成服务端→客户端的会话记录；tail 直接追加到密文之后，
// 用于构造截断记录。
func s2cWire(t *testing.T, sk *crypto.StreamKeys, records [][]protocol.Frame, tail []byte) []byte {
	t.Helper()

	var wire bytes.Buffer
	w, err := sk.NewWriter(&wire, crypto.DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	for _, frames := range records {
		require.NoError(t, w.WriteRecord(protocol.EncodeFrames(frames)))
	}
	wire.Write(tail)
	return wire.Bytes()
}

func s2cReader(t *testing.T, records [][]protocol.Frame, tail []byte) *crypto.DecryptedReader {
	t.Helper()

	sk := s2cKeys(t)
	rx, err := sk.NewReader(bytes.NewReader(s2cWire(t, sk, records, tail)), crypto.DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	return rx
}

// runRemoteCopy 用 net.Pipe 充当本地连接，返回实际写入的字节与拷贝结果。
func runRemoteCopy(t *testing.T, rx *crypto.DecryptedReader) (string, error) {
	t.Helper()

	local, peer := net.Pipe()
	defer local.Close() //nolint:errcheck
	defer peer.Close()  //nolint:errcheck

	var written bytes.Buffer
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		_, _ = io.Copy(&written, peer)
	}()

	m := stats.NewStreamMeter("client", "test")
	defer m.Close()

	err := (&StreamHandler{}).copyRemoteToLocal(rx, local, func() {}, m)
	_ = local.Close() // 让 io.Copy 退出。
	<-drained

	return written.String(), err
}

type countingReader struct {
	r io.Reader
	n atomic.Int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n.Add(int64(n))
	return n, err
}

// blockingWriteConn 让第一次本地写停住，直到测试调用 unblock；其余方法不会被 copy 使用。
type blockingWriteConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	start   sync.Once
	stop    sync.Once
}

func newBlockingWriteConn() *blockingWriteConn {
	return &blockingWriteConn{started: make(chan struct{}), release: make(chan struct{})}
}

func (c *blockingWriteConn) Write(p []byte) (int, error) {
	c.start.Do(func() { close(c.started) })
	<-c.release
	return len(p), nil
}

func (c *blockingWriteConn) unblock() {
	c.stop.Do(func() { close(c.release) })
}
