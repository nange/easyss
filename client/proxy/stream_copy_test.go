package proxy

import (
	"bytes"
	"io"
	"net"
	"testing"

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
		require.Error(t, err)
		require.NotErrorIs(t, err, ErrStreamReset)
		require.Equal(t, "ok", got)
	})
}

// s2cReader 把 records 依次封装成服务端→客户端的会话记录；tail 直接追加到密文之后，
// 用于构造截断记录。
func s2cReader(t *testing.T, records [][]protocol.Frame, tail []byte) *crypto.DecryptedReader {
	t.Helper()

	masterKey, err := crypto.DeriveMasterKey("copy-remote-to-local")
	require.NoError(t, err)
	salt, err := crypto.GenerateSalt()
	require.NoError(t, err)
	sk, err := crypto.NewStreamKeys(masterKey, salt, config.EndpointTCP)
	require.NoError(t, err)

	var wire bytes.Buffer
	w, err := sk.NewWriter(&wire, crypto.DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	for _, frames := range records {
		require.NoError(t, w.WriteRecord(protocol.EncodeFrames(frames)))
	}
	wire.Write(tail)

	rx, err := sk.NewReader(&wire, crypto.DirS2C, protocol.MethodAES256GCM)
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
