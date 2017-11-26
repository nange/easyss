package cipherstream

import (
	cc "golang.org/x/crypto/chacha20poly1305"
)

// NewChaCha20Poly1305 creates a chacha20-poly1305 AEAD instance
func NewChaCha20Poly1305(password []byte) (AEADCipher, error) {
	key := secretKey(password)
	aead, err := cc.New(key[:])
	if err != nil {
		return nil, err
	}

	return &AEADCipherImpl{aead: aead}, nil
}
