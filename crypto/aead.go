package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"

	cc "golang.org/x/crypto/chacha20poly1305"
)

type Encryptor interface {
	Encrypt(plaintext, aad []byte, nonce []byte) ([]byte, error)
	Decrypt(ciphertext, aad []byte, nonce []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}

type aeadEncryptor struct {
	aead cipher.AEAD
}

func (a *aeadEncryptor) Encrypt(plaintext, aad []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("crypto: invalid nonce size %d, want %d", len(nonce), a.aead.NonceSize())
	}
	dst := a.aead.Seal(nil, nonce, plaintext, aad)
	return dst, nil
}

func (a *aeadEncryptor) Decrypt(ciphertext, aad []byte, nonce []byte) ([]byte, error) {
	if len(nonce) != a.aead.NonceSize() {
		return nil, fmt.Errorf("crypto: invalid nonce size %d, want %d", len(nonce), a.aead.NonceSize())
	}
	plaintext, err := a.aead.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func (a *aeadEncryptor) NonceSize() int {
	return a.aead.NonceSize()
}

func (a *aeadEncryptor) Overhead() int {
	return a.aead.Overhead()
}

func NewAES256GCM(key []byte) (Encryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: AES-256-GCM requires 32-byte key")
	}
	blk, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(blk)
	if err != nil {
		return nil, err
	}
	return &aeadEncryptor{aead: aead}, nil
}

func NewChaCha20Poly1305(key []byte) (Encryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: ChaCha20-Poly1305 requires 32-byte key")
	}
	aead, err := cc.New(key)
	if err != nil {
		return nil, err
	}
	return &aeadEncryptor{aead: aead}, nil
}
