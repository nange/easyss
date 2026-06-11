package crypto

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/nange/easyss/v3/protocol"
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

	if _, err := rw.w.Write(lenBuf[:]); err != nil {
		return fmt.Errorf("crypto: write cipher_len: %w", err)
	}
	if _, err := rw.w.Write(ciphertext); err != nil {
		return fmt.Errorf("crypto: write ciphertext: %w", err)
	}
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
		return nil, fmt.Errorf("crypto: read cipher_len: %w", err)
	}

	cipherLen := int(lenBuf[0])<<16 | int(lenBuf[1])<<8 | int(lenBuf[2])
	if cipherLen == 0 {
		return nil, fmt.Errorf("crypto: zero-length ciphertext")
	}
	if cipherLen > MaxCipherRecordSize {
		return nil, fmt.Errorf("crypto: ciphertext exceeds max %d, got %d", MaxCipherRecordSize, cipherLen)
	}

	ciphertext := make([]byte, cipherLen)
	if _, err := io.ReadFull(rr.r, ciphertext); err != nil {
		return nil, fmt.Errorf("crypto: read ciphertext: %w", err)
	}

	nonce := rr.counter.Next()
	plaintext, err := rr.enc.Decrypt(ciphertext, rr.aad, nonce[:])
	if err != nil {
		return nil, fmt.Errorf("crypto: decrypt record: %w", err)
	}

	return plaintext, nil
}
