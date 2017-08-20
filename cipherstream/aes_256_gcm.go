package cipherstream

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

type Aes256GCM struct {
	aead cipher.AEAD
}

// aes256GCMKey generates a random 256-bit key for GCMEncrypt() and GCMDecrypt()
func aes256GCMKey(password []byte) *[32]byte {
	key := [32]byte{}

	enkey := pbkdf2.Key(password, []byte("easyss-subkey"), 4096, 32, sha256.New)
	copy(key[:], enkey)

	return &key
}

// NewAes256GCM creates a aes-gcm AEAD instance
func NewAes256GCM(password []byte) (AEADCipher, error) {
	key := aes256GCMKey(password)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &Aes256GCM{aead: aead}, nil
}

// Encrypt encrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aes *Aes256GCM) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	nonce := make([]byte, aes.aead.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return aes.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AES-GCM.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aes *Aes256GCM) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aes.aead.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return aes.aead.Open(nil,
		ciphertext[:aes.aead.NonceSize()],
		ciphertext[aes.aead.NonceSize():],
		nil,
	)
}

// NonceSize return underlying aead nonce size
func (aes *Aes256GCM) NonceSize() int {
	return aes.aead.NonceSize()
}

// Overhead return underlying aead overhead size
func (aes *Aes256GCM) Overhead() int {
	return aes.aead.Overhead()
}
