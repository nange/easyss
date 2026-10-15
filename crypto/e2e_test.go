package crypto

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/nange/easyss/v3/protocol"
	"github.com/stretchr/testify/require"
)

func TestRecordRoundTrip(t *testing.T) {
	masterKey, _ := DeriveMasterKey("e2e-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, counter, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)

	aad := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, counter, aad)

	plaintext := []byte("hello from v3 end-to-end test")
	err = w.WriteRecord(plaintext)
	require.NoError(t, err)
	require.Greater(t, buf.Len(), 3)

	decEnc, decCounter, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	r := NewRecordReader(&buf, decEnc, decCounter, decAAD)
	decrypted, err := r.ReadRecord()
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestRecordWriterFlushesAfterCompleteRecord(t *testing.T) {
	masterKey, _ := DeriveMasterKey("flush-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	// WriteRecord 不应自动 flush，无论记录多大。
	// 由调用方（shaper）负责调用 Flush()。
	//
	// writes 计数为 1 是刻意的：长度前缀与密文共用同一块池缓冲、一次写出，
	// 好让整条记录（前缀 + 明文 + 标签）落在 bytespool 的 64KB 档位内。上游
	// writer 完全可能对每次 Write 都立即落地（客户端的裸 io.PipeWriter 就是，
	// 见 RecordWriter.WriteRecord 的说明），所以这个次数是线上字节之外的
	// 真实成本，不能随手拆成两次。
	w := &flushBuffer{}
	rw := NewRecordWriter(w, enc, counter, aad)
	require.NoError(t, rw.WriteRecord([]byte("hello")))
	require.Equal(t, recordWriteCalls, w.writes, "前缀与密文共用一块缓冲，一次写出")
	require.Equal(t, 0, w.flushes, "WriteRecord should not auto-flush")
	require.Greater(t, w.Len(), 3)

	// 显式调用 Flush() 应始终执行 flush。
	rw.Flush()
	require.Equal(t, 1, w.flushes, "explicit Flush() should flush")

	// 大记录同样不应自动 flush。
	large := make([]byte, 32*1024)
	w2 := &flushBuffer{}
	enc2, counter2, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	rw2 := NewRecordWriter(w2, enc2, counter2, aad)
	require.NoError(t, rw2.WriteRecord(large))
	require.Equal(t, recordWriteCalls, w2.writes)
	require.Equal(t, 0, w2.flushes, "large record should not auto-flush")
	rw2.Flush()
	require.Equal(t, 1, w2.flushes, "explicit Flush() should flush after large record")
}

// recordWriteCalls 是一条记录落到 io.Writer 上的写次数：长度前缀与密文共用
// 同一块池缓冲，因此一次搞定。
const recordWriteCalls = 1

type flushBuffer struct {
	bytes.Buffer
	writes  int
	flushes int
}

func (fb *flushBuffer) Write(p []byte) (int, error) {
	fb.writes++
	return fb.Buffer.Write(p)
}

func (fb *flushBuffer) Flush() {
	fb.flushes++
}

// capRecordingBuffer 记录每一笔写入的长度与容量，用来断言"整条记录（前缀 +
// 密文）取样于同一块池缓冲，且落在 64KB 档位内"。
type capRecordingBuffer struct {
	parts []int // 每笔写入的长度
	caps  []int // 每笔写入引用的缓冲区容量
}

func (b *capRecordingBuffer) Write(p []byte) (int, error) {
	b.parts = append(b.parts, len(p))
	b.caps = append(b.caps, cap(p))
	return len(p), nil
}

// TestRecordWriterSingleWriteKeepsWireFormat 固定"记录层只写一次、且线上格式
// 不变"：写出的字节必须与"长度前缀 + 独立加密出的密文"逐字节相等。线上格式是
// 跨版本契约，任何重构都不允许让它漂移。
//
// 它同时是"前缀与密文确实共用同一块缓冲"的证据：WriteRecord 用 buf[3:3] 作为
// Seal 的目标、再从 buf 切出记录，一旦 Seal 另分配了一块，写出去的字节就会是
// 缓冲区里的残留数据，下面的等值断言立刻失败。
func TestRecordWriterSingleWriteKeepsWireFormat(t *testing.T) {
	masterKey, _ := DeriveMasterKey("single-write-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	for _, size := range []int{0, 1, 13, 1024, protocol.MaxRecordPlaintext} {
		t.Run(fmt.Sprintf("plaintext=%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}

			// 被测实现：WriteRecord 一次写出整条记录。
			var got bytes.Buffer
			enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
			require.NoError(t, err)
			require.NoError(t, NewRecordWriter(&got, enc, counter, aad).WriteRecord(plaintext))

			// 参照实现：长度前缀 + 独立加密的密文，拼接成同一条记录。
			refEnc, refCounter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
			require.NoError(t, err)
			nonce := refCounter.Next()
			cipherLen := len(plaintext) + refEnc.Overhead()
			ref := make([]byte, protocol.MaxCipherLenSize)
			ref[0] = byte(cipherLen >> 16)
			ref[1] = byte(cipherLen >> 8)
			ref[2] = byte(cipherLen)
			ciphertext, err := refEnc.Encrypt(plaintext, aad, nonce[:])
			require.NoError(t, err)

			require.Equal(t, append(ref, ciphertext...), got.Bytes(),
				"线上字节必须与前缀 + 独立密文的拼接完全一致")
		})
	}
}

// TestRecordWriterKeepsCipherBufferIn64KClass 固定"整条记录取样于池的 64KB 档"：
// 记录占用的池请求是 3 字节长度前缀 + 明文 + AEAD 标签，因此明文上限
// (protocol.MaxRecordPlaintext) 处仍落在 64KB 档；上限一旦被调高到 65,518 以上，
// 整块记录就会跳到 128KB 档，为最后十几字节付一倍的池保留与瞬时分配。
//
// 断言的是交给 io.Writer 的那块缓冲的 cap，因为字节池传下去的就是它本身——
// 这是"没有额外复制"的直接证据。
func TestRecordWriterKeepsCipherBufferIn64KClass(t *testing.T) {
	masterKey, _ := DeriveMasterKey("cipher-class-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	plaintext := make([]byte, protocol.MaxRecordPlaintext)
	rec := &capRecordingBuffer{}
	enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	require.NoError(t, NewRecordWriter(rec, enc, counter, aad).WriteRecord(plaintext))

	require.Len(t, rec.parts, recordWriteCalls)
	require.Equal(t, protocol.MaxCipherLenSize+len(plaintext)+protocol.MaxTagOverhead, rec.parts[0],
		"整条记录（前缀 + 密文）必须在同一笔写入里")
	require.Equal(t, 64*1024, rec.caps[0],
		"明文上限处的记录必须仍落在池的 64KB 档位")
}

// TestWriteRecordRejectsPlaintextAboveRecordCeiling 固定**写入侧**的上限就是
// protocol.MaxRecordPlaintext：它同时被 shaper 用作单帧校验、预冲刷边界与填充
// 预算，两侧不一致会让整形器攒出加密层拒绝的明文，把正常的流打断。
//
// 读侧刻意更宽松（MaxCipherRecordSize 仍按线上格式推导），以便解码旧对端发来的
// 64KB 明文记录；这条不对称是本测试要守住的。
func TestWriteRecordRejectsPlaintextAboveRecordCeiling(t *testing.T) {
	masterKey, _ := DeriveMasterKey("record-ceiling-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	// 约束链本身必须自洽：最大合法单帧放得下，且线上长度仍落在 64KB 档内。
	require.GreaterOrEqual(t, protocol.MaxRecordPlaintext, protocol.MaxUDPDataSize+protocol.FrameHeaderSize,
		"明文上限小于最大合法单帧，最大的 UDP 数据报会被判成超限")
	require.LessOrEqual(t, protocol.MaxRecordPlaintext+protocol.MaxCipherLenSize+protocol.MaxTagOverhead, 64*1024,
		"明文上限越过了池的 64KB 档位")
	require.Greater(t, MaxCipherRecordSize, protocol.MaxRecordPlaintext+protocol.MaxTagOverhead,
		"解码侧上限不应跟着写入侧一起收紧，否则无法解码旧对端的最大记录")

	enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	rw := NewRecordWriter(&bytes.Buffer{}, enc, counter, aad)

	require.NoError(t, rw.WriteRecord(make([]byte, protocol.MaxRecordPlaintext)),
		"上限本身必须可写")
	require.Error(t, rw.WriteRecord(make([]byte, protocol.MaxRecordPlaintext+1)),
		"超过上限的明文必须被拒绝，而不是落进 128KB 档")
}

// TestAEADOverheadMatchesProtocolCeiling 守住 protocol.MaxTagOverhead 与真实
// AEAD 标签长度的耦合：protocol 是记录格式的定义方、不依赖 crypto 包，因此这条
// 关系只能由测试约束。标签一旦变长，"明文上限 + 3 + 标签 ≤ 64KB"的算术就不再
// 成立，整条记录会跳进 128KB 档。
func TestAEADOverheadMatchesProtocolCeiling(t *testing.T) {
	masterKey, _ := DeriveMasterKey("tag-overhead-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	for _, method := range []protocol.Method{protocol.MethodAES256GCM, protocol.MethodChaCha20Poly1305} {
		enc, _, err := sk.newEncryptor(sessionPhase, DirC2S, method)
		require.NoError(t, err)
		require.LessOrEqual(t, enc.Overhead(), protocol.MaxTagOverhead,
			"method=%v 的 AEAD 标签长度超过了 protocol.MaxTagOverhead", method)
	}
}

func TestHandshakeRecordRoundTrip(t *testing.T) {
	masterKey, _ := DeriveMasterKey("handshake-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)

	aad := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	hs := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   protocol.ProtoTCP,
		Method:  protocol.MethodAES256GCM,
		Target:  "example.com:443",
	}

	hsFrame := protocol.NewFrameHANDSHAKE(hs)
	firstData := protocol.NewFrameDATA([]byte("hello"))
	frames := []protocol.Frame{hsFrame, firstData}

	plaintext := protocol.EncodeFrames(frames)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	err = w.WriteRecord(plaintext)
	require.NoError(t, err)

	first, err := sk.ReadFirstRecord(&buf)
	require.NoError(t, err)
	require.Equal(t, "example.com:443", first.Handshake.Target)
	require.Equal(t, protocol.ProtoTCP, first.Handshake.Proto)
	require.Len(t, first.Leftover, 1)
	require.Equal(t, protocol.FrameDATA, first.Leftover[0].Type)
	require.Equal(t, "hello", string(first.Leftover[0].Payload))
}

func TestDecryptedReaderReturnsAllFramesInRecord(t *testing.T) {
	masterKey, _ := DeriveMasterKey("multi-frame-reader-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.newEncryptor(sessionPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	frames := []protocol.Frame{
		protocol.NewFrameDATA([]byte("one")),
		protocol.NewFramePADDING(8),
		protocol.NewFrameDATA([]byte("two")),
		protocol.NewFrameFIN(),
	}

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	require.NoError(t, w.WriteRecord(protocol.EncodeFrames(frames)))

	decEnc, decCtr, err := sk.newEncryptor(sessionPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	dr := NewDecryptedReader(&buf, aad, decEnc, decCtr)

	for _, want := range frames {
		got, err := dr.ReadFrame()
		require.NoError(t, err)
		require.Equal(t, want.Type, got.Type)
		require.Equal(t, len(want.Payload), len(got.Payload))
		if len(want.Payload) > 0 {
			require.Equal(t, want.Payload, got.Payload)
		}
	}
}

func TestMultipleRecords(t *testing.T) {
	masterKey, _ := DeriveMasterKey("multi-record-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)

	records := [][]byte{
		[]byte("record one"),
		[]byte("record two"),
		[]byte("record three"),
	}

	for _, rec := range records {
		err = w.WriteRecord(rec)
		require.NoError(t, err)
	}

	decEnc, decCtr, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	r := NewRecordReader(&buf, decEnc, decCtr, decAAD)

	for i, expected := range records {
		got, err := r.ReadRecord()
		require.NoError(t, err)
		require.Equal(t, expected, got, "record %d mismatch", i)
	}
}

func TestRecordTamperDetection(t *testing.T) {
	masterKey, _ := DeriveMasterKey("tamper-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	err = w.WriteRecord([]byte("secret data"))
	require.NoError(t, err)

	raw := buf.Bytes()
	raw[len(raw)-1] ^= 0xFF

	decEnc, decCtr, err := sk.newEncryptor(bootstrapPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := buildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	r := NewRecordReader(bytes.NewReader(raw), decEnc, decCtr, decAAD)
	_, err = r.ReadRecord()
	require.Error(t, err, "tampered data should fail decryption")
}
