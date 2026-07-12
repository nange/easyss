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
	MaxCipherRecordSize = protocol.MaxPlainRecordSize + 16 // max plaintext + AEAD tag
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

func (rw *RecordWriter) WriteRecord(plaintext []byte) error {
	if len(plaintext) > rw.maxPlain {
		return fmt.Errorf("crypto: plaintext exceeds max %d bytes", rw.maxPlain)
	}

	nonce := rw.counter.Next()

	cipherLen := len(plaintext) + rw.enc.Overhead()
	if cipherLen > 0xFFFFFF {
		return fmt.Errorf("crypto: ciphertext too large: %d bytes", cipherLen)
	}

	record := bytespool.Get(protocol.MaxCipherLenSize + cipherLen)
	record[0] = byte(cipherLen >> 16)
	record[1] = byte(cipherLen >> 8)
	record[2] = byte(cipherLen)

	ciphertext, err := rw.enc.EncryptInto(record[protocol.MaxCipherLenSize:], plaintext, rw.aad, nonce[:])
	if err != nil {
		bytespool.MustPut(record)
		return fmt.Errorf("crypto: encrypt record: %w", err)
	}

	recordLen := protocol.MaxCipherLenSize + len(ciphertext)
	n, err := rw.w.Write(record[:recordLen])
	bytespool.MustPut(record)
	if err != nil {
		return fmt.Errorf("crypto: write record: %w", err)
	}
	if n != recordLen {
		return io.ErrShortWrite
	}

	stats.RecordBytesSent(recordLen)
	stats.RecordRecordWritten()

	return nil
}

// Flush triggers an immediate flush of the underlying writer if it supports
// flushing (e.g. HTTP/2 ResponseWriter with a 4KB bufio buffer). WriteRecord
// does not auto-flush; callers (typically the shaper) are responsible for
// calling Flush after small records. For records larger than the HTTP/2
// bufio buffer (4KB), the Go HTTP/2 server already sends data directly via
// chunkWriter, making Flush a no-op.
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
