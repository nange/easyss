package cipherstream

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/pbkdf2"
)

type AEADCipher interface {
	Encrypt(dst, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(dst, ciphertext []byte) (plaintext []byte, err error)
	NonceSize() int
	Overhead() int
}

// secretKey generates a random 256-bit key
func secretKey(password []byte) *[32]byte {
	key := [32]byte{}

	enkey := pbkdf2.Key(password, []byte("easyss-subkey"), 4096, 32, sha256.New)
	copy(key[:], enkey)

	return &key
}

type AEADCipherImpl struct {
	aead cipher.AEAD
}

// Encrypt encrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Encrypt(dst, plaintext []byte) (ciphertext []byte, err error) {
	nonceSize := aci.aead.NonceSize()

	var nonceBuf [32]byte
	nonce := nonceBuf[:nonceSize]

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	dst = append(dst, nonce...)
	return aci.aead.Seal(dst, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Decrypt(dst, ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aci.aead.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return aci.aead.Open(dst,
		ciphertext[:aci.aead.NonceSize()],
		ciphertext[aci.aead.NonceSize():],
		nil,
	)
}

// NonceSize return underlying aead nonce size
func (aci *AEADCipherImpl) NonceSize() int {
	return aci.aead.NonceSize()
}

// Overhead return underlying aead overhead size
func (aci *AEADCipherImpl) Overhead() int {
	return aci.aead.Overhead()
}
