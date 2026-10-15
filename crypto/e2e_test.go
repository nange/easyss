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
	// writes 计数为 2 是刻意的：长度前缀与密文分两次写出，好让密文缓冲
	// 正好落在 bytespool 的 64KB 档位内（把 3 字节前缀也算进同一次 Get 会让
	// 最大记录跳到 128KB 档）。两次写之间不 flush，这正是本测试要守的不变量。
	w := &flushBuffer{}
	rw := NewRecordWriter(w, enc, counter, aad)
	require.NoError(t, rw.WriteRecord([]byte("hello")))
	require.Equal(t, recordWriteCalls, w.writes, "长度前缀与密文各写一次，且不额外 flush")
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

// recordWriteCalls 是一条记录落到 io.Writer 上的写次数：长度前缀一次、密文一次。
const recordWriteCalls = 2

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

// capRecordingBuffer 记录每一笔写入的长度与容量，用来断言"长度前缀没有和
// 密文挤在同一次池请求里"。
type capRecordingBuffer struct {
	parts []int // 每笔写入的长度
	caps  []int // 每笔写入引用的缓冲区容量
}

func (b *capRecordingBuffer) Write(p []byte) (int, error) {
	b.parts = append(b.parts, len(p))
	b.caps = append(b.caps, cap(p))
	return len(p), nil
}

// TestRecordWriterPrefixSplitKeepsWireFormat 固定"拆分长度前缀不改动线上格式"：
// 两次写出的字节拼起来，必须与旧实现"长度前缀 + 密文放在同一块缓冲里一次写出"
// 的结果逐字节相等。线上格式是跨版本契约，任何重构都不允许让它漂移。
func TestRecordWriterPrefixSplitKeepsWireFormat(t *testing.T) {
	masterKey, _ := DeriveMasterKey("prefix-split-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	aad := buildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	for _, size := range []int{0, 1, 1024, protocol.MaxPlainRecordSize - protocol.MaxTagOverhead} {
		t.Run(fmt.Sprintf("plaintext=%d", size), func(t *testing.T) {
			plaintext := make([]byte, size)
			for i := range plaintext {
				plaintext[i] = byte(i)
			}

			// 新实现：前缀与密文分两次写。
			var split bytes.Buffer
			enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
			require.NoError(t, err)
			require.NoError(t, NewRecordWriter(&split, enc, counter, aad).WriteRecord(plaintext))

			// 参照实现：与旧代码逐行相同（前缀与密文同块一次写出）。
			refEnc, refCounter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
			require.NoError(t, err)
			nonce := refCounter.Next()
			cipherLen := len(plaintext) + refEnc.Overhead()
			record := make([]byte, protocol.MaxCipherLenSize+cipherLen)
			record[0] = byte(cipherLen >> 16)
			record[1] = byte(cipherLen >> 8)
			record[2] = byte(cipherLen)
			ciphertext, err := refEnc.EncryptInto(record[protocol.MaxCipherLenSize:], plaintext, aad, nonce[:])
			require.NoError(t, err)

			require.Equal(t, record[:protocol.MaxCipherLenSize+len(ciphertext)], split.Bytes(),
				"拆分成两次写之后线上字节必须与旧实现完全一致")
		})
	}
}

// TestRecordWriterKeepsCipherBufferIn64KClass 固定"长度前缀不占用池请求"：
// 密文缓冲按密文长度取块，因此最大记录（明文 = MaxPlainRecordSize - 标签）
// 仍然落在池的 64KB 档位；若把 3 字节前缀也算进同一次 Get，密文长度 65,536
// 会因为那 3 字节跳到 128KB 档，为 16 字节的溢出付一倍的池保留与瞬时分配。
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

	// 明文上限 = MaxPlainRecordSize - 标签；记录层自身的上限比它更高，
	// 因此这里显式按协议允许的最大记录构造。
	plaintext := make([]byte, protocol.MaxPlainRecordSize-protocol.MaxTagOverhead)
	rec := &capRecordingBuffer{}
	enc, counter, err := sk.newEncryptor(sessionPhase, DirS2C, protocol.MethodAES256GCM)
	require.NoError(t, err)
	require.NoError(t, NewRecordWriter(rec, enc, counter, aad).WriteRecord(plaintext))

	require.Len(t, rec.parts, recordWriteCalls)
	require.Equal(t, protocol.MaxCipherLenSize, rec.parts[0], "第一笔写必须是长度前缀")
	require.Equal(t, len(plaintext)+protocol.MaxTagOverhead, rec.parts[1], "第二笔写是密文")
	for i, c := range rec.caps {
		require.LessOrEqual(t, c, 64*1024,
			"第 %d 笔写引用的池缓冲 cap = %d，超过了 64KB 档位", i, c)
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
