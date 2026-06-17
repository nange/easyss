package crypto

import (
	"encoding/binary"
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
	ciphertext, err := rw.enc.Encrypt(plaintext, rw.aad, nonce[:])
	if err != nil {
		return fmt.Errorf("crypto: encrypt record: %w", err)
	}

	var lenBuf [protocol.MaxCipherLenSize]byte
	if len(ciphertext) > 0xFFFFFF {
		return fmt.Errorf("crypto: ciphertext too large: %d bytes", len(ciphertext))
	}
	binary.BigEndian.PutUint16(lenBuf[1:3], uint16(len(ciphertext)&0xFFFF))
	lenBuf[0] = byte(len(ciphertext) >> 16)

	record := bytespool.Get(protocol.MaxCipherLenSize + len(ciphertext))
	copy(record[:protocol.MaxCipherLenSize], lenBuf[:])
	copy(record[protocol.MaxCipherLenSize:], ciphertext)

	recordLen := len(record)
	n, err := rw.w.Write(record)
	bytespool.MustPut(record)
	if err != nil {
		return fmt.Errorf("crypto: write record: %w", err)
	}
	if n != recordLen {
		return io.ErrShortWrite
	}

	stats.RecordBytesSent(recordLen)
	stats.RecordRecordWritten()

	if flusher, ok := rw.w.(recordFlusher); ok {
		flusher.Flush()
	}

	return nil
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
