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

	// WriteRecord 不自动 flush，由调用方（shaper）负责 Flush()。writes 计数为 1 是刻意的：
	// 前缀与密文共用同一块池缓冲、一次写出，整条记录才落在 bytespool 的 64KB 档位内，
	// 而上游 writer 可能对每次 Write 都立即落地，所以这个次数是真实成本。
	w := &flushBuffer{}
	rw := NewRecordWriter(w, enc, counter, aad)
	require.NoError(t, rw.WriteRecord([]byte("hello")))
	require.Equal(t, recordWriteCalls, w.writes, "前缀与密文共用一块缓冲，一次写出")
	require.Equal(t, 0, w.flushes, "WriteRecord should not auto-flush")
	require.Greater(t, w.Len(), 3)

	rw.Flush()
	require.Equal(t, 1, w.flushes, "explicit Flush() should flush")

	// 大记录同样不自动 flush。"大"取写入上限本身：它既是最大的一条记录，也是唯一会走到池档位边界的尺寸。
	large := make([]byte, protocol.MaxWriteRecordPlaintext)
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

// recordWriteCalls 是一条记录落到 io.Writer 上的写次数：前缀与密文共用同一块池缓冲，一次搞定。
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

// capRecordingBuffer 记录每笔写入的长度与容量，用来断言整条记录取样于同一块池缓冲且落在 64KB 档位内。
type capRecordingBuffer struct {
	parts []int // 每笔写入的长度
	caps  []int // 每笔写入引用的缓冲区容量
}

func (b *capRecordingBuffer) Write(p []byte) (int, error) {
	b.parts = append(b.parts, len(p))
	b.caps = append(b.caps, cap(p))
	return len(p), nil
}

// TestRecordWriterSingleWriteKeepsWireFormat 固定线上格式（长度前缀 + 独立加密的密文）不漂移，
// 同时证明前缀与密文共用同一块缓冲：WriteRecord 用 buf[3:3] 作 Seal 目标，一旦另分配就会写出残留数据。
func TestRecordWriterSingleWriteKeepsWireFormat(t *testing.T) {
	masterKey, _ := DeriveMasterKey("single-write-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	for _, size := range []int{0, 1, 13, 1024, protocol.MaxWriteRecordPlaintext} {
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

// TestRecordWriterKeepsCipherBufferInPoolClass 固定两条尺寸链的池档位：数据报上限
// （MaxUDPDataSize + 帧头 = 16,365）落在 16KB 档，记录写入上限（65,517）落在 64KB 档。
// 上限调大整块就跳一档；断言交给 io.Writer 那块缓冲的 cap，"没有额外复制"的直接证据。
func TestRecordWriterKeepsCipherBufferInPoolClass(t *testing.T) {
	masterKey, _ := DeriveMasterKey("cipher-class-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	tests := []struct {
		name      string
		plaintext int
		wantCap   int
	}{
		{"datagram frame", protocol.MaxUDPDataSize + protocol.FrameHeaderSize, protocol.UDPPoolClassSize},
		{"record ceiling", protocol.MaxWriteRecordPlaintext, protocol.MaxReadRecordPlaintext},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plaintext := make([]byte, tt.plaintext)
			rec := &capRecordingBuffer{}
			enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
			require.NoError(t, err)
			require.NoError(t, NewRecordWriter(rec, enc, counter, aad).WriteRecord(plaintext))

			require.Len(t, rec.parts, recordWriteCalls)
			require.Equal(t, protocol.MaxCipherLenSize+len(plaintext)+protocol.MaxTagOverhead, rec.parts[0],
				"整条记录（前缀 + 密文）必须在同一笔写入里")
			require.Equal(t, tt.wantCap, rec.caps[0],
				"满记录必须仍落在对应的池档位内")
		})
	}
}

// TestWriteRecordRejectsPlaintextAboveRecordCeiling 固定写入侧上限就是 protocol.MaxWriteRecordPlaintext：
// shaper 同时用它做单帧校验、预冲刷边界与填充预算，两侧不一致会让整形器攒出加密层拒绝的明文。
// 读侧刻意更宽松（MaxCipherRecordSize 仍按线上格式推导），以便解码旧对端的 64KB 明文记录。
func TestWriteRecordRejectsPlaintextAboveRecordCeiling(t *testing.T) {
	masterKey, _ := DeriveMasterKey("record-ceiling-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	// 约束链本身必须自洽：最大数据报帧放得下，且满记录正好落在 64KB 档位内。
	require.GreaterOrEqual(t, protocol.MaxWriteRecordPlaintext, protocol.MaxUDPDataSize+protocol.FrameHeaderSize,
		"明文上限小于最大数据报帧，最大的 UDP 数据报会被判成超限")
	require.Equal(t, protocol.MaxReadRecordPlaintext,
		protocol.MaxWriteRecordPlaintext+protocol.MaxCipherLenSize+protocol.MaxTagOverhead,
		"明文上限没有贴紧 64KB 档位")
	require.Greater(t, MaxCipherRecordSize, protocol.MaxWriteRecordPlaintext+protocol.MaxTagOverhead,
		"解码侧上限不应跟着写入侧一起收紧，否则无法解码旧对端的最大记录")

	enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	rw := NewRecordWriter(&bytes.Buffer{}, enc, counter, aad)

	require.NoError(t, rw.WriteRecord(make([]byte, protocol.MaxWriteRecordPlaintext)),
		"上限本身必须可写")
	require.Error(t, rw.WriteRecord(make([]byte, protocol.MaxWriteRecordPlaintext+1)),
		"超过上限的明文必须被拒绝，而不是落进 128KB 档")
}

// TestAEADOverheadMatchesProtocolCeiling 守住 protocol.MaxTagOverhead 与真实 AEAD 标签长度的耦合：
// protocol 不依赖 crypto，只能由测试约束；标签变长后"明文上限 + 3 + 标签 = 64KB"的算术就不再成立。
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

func TestDecryptedReaderReusesFrameBufAcrossRecords(t *testing.T) {
	masterKey, _ := DeriveMasterKey("frame-buf-reuse-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.newEncryptor(sessionPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := buildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	const framesPerRecord = 12
	makeFrames := func() []protocol.Frame {
		frames := make([]protocol.Frame, 0, framesPerRecord)
		for i := range framesPerRecord {
			frames = append(frames, protocol.NewFrameDATA([]byte{byte(i)}))
		}
		return frames
	}

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	require.NoError(t, w.WriteRecord(protocol.EncodeFrames(makeFrames())))
	require.NoError(t, w.WriteRecord(protocol.EncodeFrames(makeFrames())))

	decEnc, decCtr, err := sk.newEncryptor(sessionPhase, DirC2S, protocol.MethodAES256GCM)
	require.NoError(t, err)
	dr := NewDecryptedReader(&buf, aad, decEnc, decCtr)

	for range framesPerRecord {
		_, err := dr.ReadFrame()
		require.NoError(t, err)
	}
	require.GreaterOrEqual(t, cap(dr.frameBuf), framesPerRecord)

	backing := &dr.frameBuf[:1][0]
	for range framesPerRecord {
		_, err := dr.ReadFrame()
		require.NoError(t, err)
	}
	require.Same(t, backing, &dr.frameBuf[:1][0])
}
