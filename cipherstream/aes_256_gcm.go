package cipherstream

import (
	"crypto/aes"
	"crypto/cipher"
)

// NewAes256GCM creates a aes-gcm AEAD instance
func NewAes256GCM(password []byte) (AEADCipher, error) {
	key := secretKey(password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AEADCipherImpl{aead: aead}, nil
}
