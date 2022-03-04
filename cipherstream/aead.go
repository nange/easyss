package cipherstream

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"github.com/nange/easyss/util"
	"golang.org/x/crypto/pbkdf2"
)

type AEADCipher interface {
	Encrypt(plaintext []byte) (ciphertext []byte, err error)
	Decrypt(ciphertext []byte) (plaintext []byte, err error)
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

var nonceBytes = util.NewBytes(24)

// Encrypt encrypts data using 256-bit AEAD.  This both hides the content of
// the data and provides a check that it hasn't been altered. Output takes the
// form nonce|ciphertext|tag where '|' indicates concatenation.
func (aci *AEADCipherImpl) Encrypt(plaintext []byte) (ciphertext []byte, err error) {
	nonce := nonceBytes.Get(aci.aead.NonceSize())
	defer nonceBytes.Put(nonce)

	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	return aci.aead.Seal(nonce, nonce, plaintext, nil), nil
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
