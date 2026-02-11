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
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	EncryptTo(dst, plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
	NonceSize() int
	Overhead() int
}

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
func (aci *AEADCipherImpl) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	nonce := make([]byte, aci.aead.NonceSize())

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return aci.aead.Seal(nonce, nonce, plaintext, nil), nil
}

// EncryptTo encrypts data using 256-bit AEAD and appends to dst.
// The dst buffer must have enough capacity to hold nonce+ciphertext+tag.
// If dst is nil, it behaves like Encrypt (allocates new buffer).
func (aci *AEADCipherImpl) EncryptTo(dst, plaintext []byte) (ciphertext []byte, err error) {
	nonceSize := aci.aead.NonceSize()

	// Ensure dst has space for nonce
	if cap(dst)-len(dst) < nonceSize {
		// If capacity is not enough, we have to append (which might reallocate)
		// Or we could panic/error if we strictly require pre-allocated buffer.
		// For safety and compatibility with standard append semantics:
		newDst := make([]byte, len(dst)+nonceSize)
		copy(newDst, dst)
		dst = newDst
	} else {
		// Expand dst to include nonce space
		dst = dst[:len(dst)+nonceSize]
	}

	// The nonce is at the end of the current dst
	nonce := dst[len(dst)-nonceSize:]

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	// Seal appends ciphertext+tag to the start of nonce (which is dst[len(dst)-nonceSize:])
	// Wait, Seal(dst, nonce, plaintext, additionalData)
	// The first argument to Seal is 'dst', where the result is appended.
	// We want the result to be appended to the buffer *before* the nonce? No.
	// Standard AEAD: nonce is IV. Output is usually nonce + ciphertext + tag.
	// So we want:
	// 1. Append nonce to dst.
	// 2. Call Seal, passing (dst, nonce, plaintext, nil).
	// Seal will append ciphertext+tag to dst.
	// So final dst will be: original_dst + nonce + ciphertext + tag.

	// Let's adjust logic:
	// We appended nonce to dst above. So 'dst' now includes the nonce at the end.
	// But Seal needs the 'dst' slice *before* the ciphertext is added.
	// So Seal(dst, nonce, ...) will append ciphertext to dst.
	// Correct.

	return aci.aead.Seal(dst, nonce, plaintext, nil), nil
}

// Decrypt decrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Expects input
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Decrypt(ciphertext []byte) (plaintext []byte, err error) {
	if len(ciphertext) < aci.aead.NonceSize() {
		return nil, errors.New("malformed ciphertext")
	}

	return aci.aead.Open(nil,
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
