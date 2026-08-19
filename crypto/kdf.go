package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize            = 16
	keySize             = 32
	masterKDFIterations = 100_000

	masterKDFInfo    = "easyss-v3-master"
	bootstrapKDFInfo = "easyss-v3-bootstrap"
	sessionKDFInfo   = "easyss-v3-session"
	probeKDFInfo     = "easyss-v3-probe"
)

func DeriveMasterKey(password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("crypto: password is empty")
	}
	key := pbkdf2.Key([]byte(password), []byte(masterKDFInfo), masterKDFIterations, keySize, sha256.New)
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

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return salt, nil
}

// ProbeToken derives the capability token for the /v3/probe endpoint.
// Client and server derive the same 16-byte value from the master key;
// base64url-encoded it is wire-identical to the x-es salt shape used by
// proxy handshakes.
func ProbeToken(masterKey []byte) (string, error) {
	reader := hkdf.New(sha256.New, masterKey, nil, []byte(probeKDFInfo))
	b := make([]byte, saltSize)
	if _, err := io.ReadFull(reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
