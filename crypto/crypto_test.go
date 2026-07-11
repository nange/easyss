package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"sync"
	"testing"

	"github.com/nange/easyss/v3/protocol"
	"github.com/stretchr/testify/require"
)

func TestDeriveMasterKey(t *testing.T) {
	key, err := DeriveMasterKey("test-password")
	require.NoError(t, err)
	require.Len(t, key, 32)

	key2, err := DeriveMasterKey("test-password")
	require.NoError(t, err)
	require.Equal(t, key, key2)

	key3, err := DeriveMasterKey("different-password")
	require.NoError(t, err)
	require.NotEqual(t, key, key3)
}

func TestGenerateSalt(t *testing.T) {
	salt, err := GenerateSalt()
	require.NoError(t, err)
	require.Len(t, salt, 16)
}

func TestDeriveBootstrapKeys(t *testing.T) {
	masterKey, _ := DeriveMasterKey("test-password")
	salt, _ := GenerateSalt()

	bk1, err := DeriveBootstrapKeys(masterKey, salt)
	require.NoError(t, err)

	bk2, err := DeriveBootstrapKeys(masterKey, salt)
	require.NoError(t, err)
	require.Equal(t, bk1, bk2)

	salt2, _ := GenerateSalt()
	bk3, _ := DeriveBootstrapKeys(masterKey, salt2)
	require.NotEqual(t, bk1.Key, bk3.Key)
}

func TestDeriveSessionKeys(t *testing.T) {
	masterKey, _ := DeriveMasterKey("test-password")
	salt, _ := GenerateSalt()

	sk1, err := DeriveSessionKeys(masterKey, salt)
	require.NoError(t, err)

	sk2, err := DeriveSessionKeys(masterKey, salt)
	require.NoError(t, err)
	require.Equal(t, sk1, sk2)

	require.NotEqual(t, sk1.C2SKey, sk1.S2CKey)
	require.NotEqual(t, sk1.C2SNoncePrefix, sk1.S2CNoncePrefix)
}

func TestCounterNonce(t *testing.T) {
	var prefix [4]byte
	prefix[0] = 0xAA

	cn := NewCounterNonce(prefix)

	n1 := cn.Next()
	require.Equal(t, prefix[0], n1[0])
	require.Equal(t, prefix[1], n1[1])

	var val1 uint64
	for i := 0; i < 8; i++ {
		val1 = (val1 << 8) | uint64(n1[4+i])
	}
	require.Equal(t, uint64(0), val1)

	n2 := cn.Next()
	var val2 uint64
	for i := 0; i < 8; i++ {
		val2 = (val2 << 8) | uint64(n2[4+i])
	}
	require.Equal(t, uint64(1), val2)

	n3 := cn.Next()
	require.NotEqual(t, n2, n3)
}

func TestAEADEncryptDecrypt(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	enc, err := NewAES256GCM(key)
	require.NoError(t, err)
	require.Equal(t, 12, enc.NonceSize())

	nonce := make([]byte, enc.NonceSize())
	_, _ = rand.Read(nonce)

	plaintext := []byte("hello world")
	aad := []byte("test-aad")

	ciphertext, err := enc.Encrypt(plaintext, aad, nonce)
	require.NoError(t, err)

	decrypted, err := enc.Decrypt(ciphertext, aad, nonce)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)

	_, err = enc.Decrypt(ciphertext, []byte("wrong-aad"), nonce)
	require.Error(t, err)
}

func TestEncryptInto(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	enc, err := NewAES256GCM(key)
	require.NoError(t, err)

	nonce := make([]byte, enc.NonceSize())
	_, _ = rand.Read(nonce)

	plaintext := []byte("hello world from EncryptInto")
	aad := []byte("test-aad")

	ciphertextStandard, err := enc.Encrypt(plaintext, aad, nonce)
	require.NoError(t, err)

	dst := make([]byte, 0, len(plaintext)+enc.Overhead())
	ciphertextInto, err := enc.EncryptInto(dst, plaintext, aad, nonce)
	require.NoError(t, err)
	require.Equal(t, ciphertextStandard, ciphertextInto)
	require.Equal(t, cap(ciphertextInto), len(plaintext)+enc.Overhead(), "EncryptInto should reuse dst backing array")

	decrypted, err := enc.Decrypt(ciphertextInto, aad, nonce)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	enc, err := NewChaCha20Poly1305(key)
	require.NoError(t, err)

	nonce := make([]byte, enc.NonceSize())
	_, _ = rand.Read(nonce)

	plaintext := []byte("test data")
	ciphertext, err := enc.Encrypt(plaintext, nil, nonce)
	require.NoError(t, err)

	decrypted, err := enc.Decrypt(ciphertext, nil, nonce)
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestStreamKeysAndRecords(t *testing.T) {
	masterKey, _ := DeriveMasterKey("test-password")
	salt, _ := GenerateSalt()

	endpoint := "/v3/tcp"
	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	plaintext := []byte("test record data")
	enc, counter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)

	aad := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NotNil(t, aad)

	var buf bytes.Buffer
	rw := NewRecordWriter(&buf, enc, counter, aad)
	err = rw.WriteRecord(plaintext)
	require.NoError(t, err)
	require.Greater(t, buf.Len(), 0)

	readerEnc, readerCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	_ = readerEnc
	_ = readerCounter
}

func TestBuildAAD(t *testing.T) {
	salt := []byte("1234567890123456")
	aad := BuildAAD("/v3/tcp", salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NotNil(t, aad)
	require.Contains(t, string(aad), "easyss-v3/v3/tcp")
}

func TestNewStreamKeysInvalidInput(t *testing.T) {
	_, err := NewStreamKeys([]byte("short"), make([]byte, 16), "/v3/tcp")
	require.Error(t, err)

	masterKey, _ := DeriveMasterKey("password")
	_, err = NewStreamKeys(masterKey, []byte("short"), "/v3/tcp")
	require.Error(t, err)
}

func TestCounterNonceConcurrentNext(t *testing.T) {
	var prefix [4]byte
	prefix[0] = 0xBB

	cn := NewCounterNonce(prefix)

	const goroutines = 8
	const callsPerGoroutine = 10000
	const total = goroutines * callsPerGoroutine

	var wg sync.WaitGroup
	wg.Add(goroutines)

	counters := make([]uint64, total)
	for g := range goroutines {
		go func(gid int) {
			defer wg.Done()
			for i := range callsPerGoroutine {
				nonce := cn.Next()
				idx := gid*callsPerGoroutine + i
				counters[idx] = binary.BigEndian.Uint64(nonce[4:])
			}
		}(g)
	}
	wg.Wait()

	seen := make(map[uint64]bool, total)
	for _, c := range counters {
		if seen[c] {
			t.Fatalf("duplicate nonce counter: %d", c)
		}
		seen[c] = true
	}

	require.Len(t, seen, total)

	for i := range total {
		require.True(t, seen[uint64(i)], "missing counter value %d", i)
	}
}
