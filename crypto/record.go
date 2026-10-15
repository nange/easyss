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
	MaxCipherRecordSize = protocol.MaxPlainRecordSize + 16 // 最大明文 + AEAD 认证标签
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
		maxPlain: protocol.MaxPlainRecordSize,
	}
}

// WriteRecord 把一条明文记录加密后写出。线上格式是
// MaxCipherLenSize(3) 字节的大端密文长度 + 密文。
//
// 长度前缀刻意不放进池化缓冲：缓冲按"密文长度"取块，因此密文恰好落在
// bytespool 的 64KB 档位内（见 protocol.MaxTagOverhead）；若把 3 字节前缀
// 也算进同一次 Get，最大记录会因这 3 字节跳到 128KB 档，为十几字节的溢出
// 付一倍的池保留与瞬时分配。代价是每条记录两次 Write——两者都落到同一层
// 缓冲（bufio 或 HTTP/2 framer），且都不会单独 flush。
func (rw *RecordWriter) WriteRecord(plaintext []byte) error {
	if len(plaintext) > rw.maxPlain {
		return fmt.Errorf("crypto: plaintext exceeds max %d bytes", rw.maxPlain)
	}

	nonce := rw.counter.Next()

	cipherLen := len(plaintext) + rw.enc.Overhead()
	if cipherLen > 0xFFFFFF {
		return fmt.Errorf("crypto: ciphertext too large: %d bytes", cipherLen)
	}

	prefix := [protocol.MaxCipherLenSize]byte{
		byte(cipherLen >> 16), byte(cipherLen >> 8), byte(cipherLen),
	}
	buf := bytespool.Get(cipherLen)
	ciphertext, err := rw.enc.EncryptInto(buf, plaintext, rw.aad, nonce[:])
	if err != nil {
		bytespool.MustPut(buf)
		return fmt.Errorf("crypto: encrypt record: %w", err)
	}

	recordLen := protocol.MaxCipherLenSize + len(ciphertext)
	err = writeFully(rw.w, prefix[:])
	if err == nil {
		err = writeFully(rw.w, ciphertext)
	}
	bytespool.MustPut(buf)
	if err != nil {
		return fmt.Errorf("crypto: write record: %w", err)
	}

	stats.RecordBytesSent(recordLen)
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
