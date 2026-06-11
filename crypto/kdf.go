package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize = 16
	keySize  = 32

	masterKDFInfo    = "easyss-v3-master"
	bootstrapKDFInfo = "easyss-v3-bootstrap"
	sessionKDFInfo   = "easyss-v3-session"
)

func DeriveMasterKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("crypto: password is empty")
	}
	key := pbkdf2.Key([]byte(password), []byte(masterKDFInfo), 4096, keySize, sha256.New)
	if len(key) != keySize {
		return nil, errors.New("crypto: failed to derive master key")
	}
	return key, nil
}

type BootstrapKeys struct {
	Key         [32]byte
	NoncePrefix [4]byte
}

func DeriveBootstrapKeys(masterKey, salt []byte) (BootstrapKeys, error) {
	var bk BootstrapKeys
	reader := hkdf.New(sha256.New, masterKey, salt, []byte(bootstrapKDFInfo))

	if _, err := io.ReadFull(reader, bk.Key[:]); err != nil {
		return bk, err
	}
	if _, err := io.ReadFull(reader, bk.NoncePrefix[:]); err != nil {
		return bk, err
	}
	return bk, nil
}

type SessionKeys struct {
	C2SKey         [32]byte
	S2CKey         [32]byte
	C2SNoncePrefix [4]byte
	S2CNoncePrefix [4]byte
}

func DeriveSessionKeys(masterKey, salt []byte) (SessionKeys, error) {
	var sk SessionKeys
	reader := hkdf.New(sha256.New, masterKey, salt, []byte(sessionKDFInfo))

	if _, err := io.ReadFull(reader, sk.C2SKey[:]); err != nil {
		return sk, err
	}
	if _, err := io.ReadFull(reader, sk.S2CKey[:]); err != nil {
		return sk, err
	}
	if _, err := io.ReadFull(reader, sk.C2SNoncePrefix[:]); err != nil {
		return sk, err
	}
	if _, err := io.ReadFull(reader, sk.S2CNoncePrefix[:]); err != nil {
		return sk, err
	}
	return sk, nil
}

func SystemEntropy(extra ...[]byte) ([]byte, error) {
	var b [32]byte
	if _, err := hmac.New(sha256.New, nil).Write([]byte("easyss-v3-entropy")); err != nil {
		return nil, err
	}
	for _, e := range extra {
		if _, err := hmac.New(sha256.New, nil).Write(e); err != nil {
			return nil, err
		}
	}
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return nil, err
	}
	return b[:], nil
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}
