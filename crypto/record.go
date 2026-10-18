package crypto

import (
	"errors"
	"fmt"
	"io"

	"github.com/nange/easyss/v3/protocol"
	"github.com/nange/easyss/v3/stats"
	"github.com/nange/easyss/v3/util/bytespool"
)

const (
	// MaxCipherRecordSize 是**解码侧**的密文长度上限，按解码侧明文上限
	// （protocol.MaxReadRecordPlaintext）加 AEAD 标签推导，而非按本进程的写入
	// 上限：它必须继续接受旧对端发来的、明文到 64KB 的记录。写入侧上限
	// protocol.MaxWriteRecordPlaintext 比 MaxReadRecordPlaintext 小 19 字节
	// （3 字节长度前缀 + 16 字节标签），正好让一条满记录落在池的 64KB 档位内。
	MaxCipherRecordSize = protocol.MaxReadRecordPlaintext + 16 // 最大明文 + AEAD 认证标签
)

type RecordWriter struct {
	w        io.Writer
	enc      Encryptor
	counter  *CounterNonce
	aad      []byte
	maxPlain int
}

type recordFlusher interface {
	Flush()
}

func NewRecordWriter(w io.Writer, enc Encryptor, counter *CounterNonce, aad []byte) *RecordWriter {
	return &RecordWriter{
		w:        w,
		enc:      enc,
		counter:  counter,
		aad:      aad,
		maxPlain: protocol.MaxWriteRecordPlaintext,
	}
}

// WriteRecord 把一条明文记录加密后写出。线上格式是
// MaxCipherLenSize(3) 字节的大端密文长度 + 密文。
//
// 长度前缀与密文共用同一块池化缓冲，也只写一次：一条记录在池里的落点就是
// "3 字节前缀 + 明文 + AEAD 标签"，明文不超过 protocol.MaxWriteRecordPlaintext
// 时整块记录仍落在 64KB 档位内；超过它才会向上跳一档（这正是 maxPlain 取
// 该常量而不是线上格式上限的原因——后者会让每条满记录都去申请一块 128KB
// 档的缓冲）。
//
// 刻意只写一次：上游 writer 完全可能对每次 Write 都立即落地——客户端写的是
// 裸 io.PipeWriter（transport/http2 的请求体），而 net/http 的 HTTP/2 transport
// 对每次 body Read 都 WriteData + bw.Flush()（Go 1.27 里那句 "this flush is
// for latency, not bandwidth" 的 TODO 尚未改写）。拆成两次写就会给每条记录多
// 一个 3 字节的 DATA 帧、多一次 flush（在 TLS 层表现为多一条十几字节的小记录），
// 既多一次系统调用，也扰动 shaper 辛苦对齐的尺寸档位——所以这里的取舍是
// "让前缀占用池请求"，而不是"多写一次"。
func (rw *RecordWriter) WriteRecord(plaintext []byte) error {
	if len(plaintext) > rw.maxPlain {
		return fmt.Errorf("crypto: plaintext exceeds max %d bytes", rw.maxPlain)
	}

	nonce := rw.counter.Next()

	cipherLen := len(plaintext) + rw.enc.Overhead()
	if cipherLen > 0xFFFFFF {
		return fmt.Errorf("crypto: ciphertext too large: %d bytes", cipherLen)
	}

	buf := bytespool.Get(protocol.MaxCipherLenSize + cipherLen)
	// 密文直接落在长度前缀之后：EncryptInto 从 dst 的起点写起（内部是
	// dst[:0] + Seal），因此传 buf[3:3] 就让密文落在 buf[3:] 上，与前缀共用
	// 同一块池缓冲。缓冲按 3+cipherLen 取块，Seal 的容量需求恰好被满足，所以它
	// 不会另分配一块。下面的 record 因此必须切自 buf 而不是回传的 ciphertext：
	// 后者只保证长度，Seal 若另分配过，它就不再指向 buf（那样写出去的就是残留
	// 数据，逐字节等价的测试会立刻失败）。
	ciphertext, err := rw.enc.EncryptInto(
		buf[protocol.MaxCipherLenSize:protocol.MaxCipherLenSize], plaintext, rw.aad, nonce[:])
	if err != nil {
		bytespool.MustPut(buf)
		return fmt.Errorf("crypto: encrypt record: %w", err)
	}

	record := buf[:protocol.MaxCipherLenSize+len(ciphertext)]
	record[0] = byte(cipherLen >> 16)
	record[1] = byte(cipherLen >> 8)
	record[2] = byte(cipherLen)

	err = writeFully(rw.w, record)
	bytespool.MustPut(buf)
	if err != nil {
		return fmt.Errorf("crypto: write record: %w", err)
	}

	stats.RecordBytesSent(len(record))
	stats.RecordRecordWritten()

	return nil
}

// writeFully 写出全部字节，短写（io.Writer 允许）归一为 io.ErrShortWrite，
// 因此调用方不必自行判断部分写入——部分写出后该流已不可信，只能整体报错，
// 与改动前"一次 Write 后检查 n == recordLen"的语义一致。
func writeFully(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err != nil {
		return err
	}
	if n != len(p) {
		return io.ErrShortWrite
	}
	return nil
}

// Flush 在底层写入器支持刷新时立即触发一次刷新（例如带 4KB bufio 缓冲的
// HTTP/2 ResponseWriter）。WriteRecord 不会自动 flush；调用方（通常是
// shaper）负责在小记录后调用 Flush。对于大于 HTTP/2 bufio 缓冲（4KB）的
// 记录，Go HTTP/2 服务器已经通过 chunkWriter 直接发送数据，Flush 成为
// 空操作。
func (rw *RecordWriter) Flush() {
	if flusher, ok := rw.w.(recordFlusher); ok {
		flusher.Flush()
	}
}

type RecordReader struct {
	r       io.Reader
	enc     Encryptor
	counter *CounterNonce
	aad     []byte
}

func NewRecordReader(r io.Reader, enc Encryptor, counter *CounterNonce, aad []byte) *RecordReader {
	return &RecordReader{
		r:       r,
		enc:     enc,
		counter: counter,
		aad:     aad,
	}
}

func (rr *RecordReader) ReadRecord() ([]byte, error) {
	var lenBuf [protocol.MaxCipherLenSize]byte
	if _, err := io.ReadFull(rr.r, lenBuf[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("crypto: read cipher_len: %w", err)
	}

	cipherLen := int(lenBuf[0])<<16 | int(lenBuf[1])<<8 | int(lenBuf[2])
	if cipherLen == 0 {
		return nil, fmt.Errorf("crypto: zero-length ciphertext")
	}
	if cipherLen > MaxCipherRecordSize {
		return nil, fmt.Errorf("crypto: ciphertext exceeds max %d, got %d", MaxCipherRecordSize, cipherLen)
	}

	ciphertext := bytespool.Get(cipherLen)
	if _, err := io.ReadFull(rr.r, ciphertext); err != nil {
		bytespool.MustPut(ciphertext)
		return nil, fmt.Errorf("crypto: read ciphertext: %w", err)
	}

	nonce := rr.counter.Next()
	plaintext, err := rr.enc.Decrypt(ciphertext, rr.aad, nonce[:])
	bytespool.MustPut(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt record: %w", err)
	}

	stats.RecordBytesRecv(protocol.MaxCipherLenSize + cipherLen)

	return plaintext, nil
}
