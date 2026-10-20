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
	// MaxCipherRecordSize 是解码侧上限，按 protocol.MaxReadRecordPlaintext 加 AEAD 标签推导，
	// 必须继续接受旧对端发来的满 64KB 明文；写入侧另由 MaxWriteRecordPlaintext 限定。
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

// 长度前缀与密文必须一次写出：net/http 的 h2 transport 对每次 body Read 都 WriteData + flush，
// 拆成两次写会多出 DATA 帧与 TLS 记录，也扰动 shaper 按 64KB 档位对齐的尺寸。
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
	// 密文必须与前缀共用同一块池缓冲，record 也必须切自 buf 而非回传的 ciphertext——
	// 后者只保证长度，Seal 若另分配过就会写出去残留数据。
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

// writeFully 写出全部字节，短写归一为 io.ErrShortWrite：部分写出后该流已不可信，只能整体报错。
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

// Flush 在底层写入器支持刷新时立即触发一次（例如带 4KB bufio 缓冲的 HTTP/2
// ResponseWriter）。WriteRecord 不会自动 flush，调用方（shaper）负责在小记录后调用它。
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
