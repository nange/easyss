package crypto

import (
	"bytes"
	"testing"

	"github.com/nange/easyss/v3/protocol"
	"github.com/stretchr/testify/require"
)

func TestRecordRoundTrip(t *testing.T) {
	masterKey, _ := DeriveMasterKey("e2e-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, counter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)

	aad := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, counter, aad)

	plaintext := []byte("hello from v3 end-to-end test")
	err = w.WriteRecord(plaintext)
	require.NoError(t, err)
	require.Greater(t, buf.Len(), 3)

	decEnc, decCounter, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	r := NewRecordReader(&buf, decEnc, decCounter, decAAD)
	decrypted, err := r.ReadRecord()
	require.NoError(t, err)
	require.Equal(t, plaintext, decrypted)
}

func TestRecordWriterFlushesAfterCompleteRecord(t *testing.T) {
	masterKey, _ := DeriveMasterKey("flush-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)
	enc, counter, err := sk.Encryptor("s2c", "session", protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := BuildAAD(endpoint, salt, "s2c", "session", protocol.MethodAES256GCM)

	w := &flushBuffer{}
	require.NoError(t, NewRecordWriter(w, enc, counter, aad).WriteRecord([]byte("hello")))
	require.Equal(t, 1, w.writes)
	require.Equal(t, 1, w.flushes)
	require.Greater(t, w.Len(), 3)
}

type flushBuffer struct {
	bytes.Buffer
	writes  int
	flushes int
}

func (fb *flushBuffer) Write(p []byte) (int, error) {
	fb.writes++
	return fb.Buffer.Write(p)
}

func (fb *flushBuffer) Flush() {
	fb.flushes++
}

func TestHandshakeRecordRoundTrip(t *testing.T) {
	masterKey, _ := DeriveMasterKey("handshake-test-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)

	aad := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	hs := protocol.Handshake{
		Version: protocol.Version3,
		Proto:   protocol.ProtoTCP,
		Method:  protocol.MethodAES256GCM,
		Target:  "example.com:443",
	}

	hsFrame := protocol.NewFrameHANDSHAKE(hs)
	firstData := protocol.NewFrameDATA([]byte("hello"))
	frames := []protocol.Frame{hsFrame, firstData}

	plaintext := protocol.EncodeFrames(frames)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	err = w.WriteRecord(plaintext)
	require.NoError(t, err)

	first, err := sk.ReadFirstRecord(&buf)
	require.NoError(t, err)
	require.Equal(t, "example.com:443", first.Handshake.Target)
	require.Equal(t, protocol.ProtoTCP, first.Handshake.Proto)
	require.Len(t, first.Leftover, 1)
	require.Equal(t, protocol.FrameDATA, first.Leftover[0].Type)
	require.Equal(t, "hello", string(first.Leftover[0].Payload))
}

func TestDecryptedReaderReturnsAllFramesInRecord(t *testing.T) {
	masterKey, _ := DeriveMasterKey("multi-frame-reader-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	frames := []protocol.Frame{
		protocol.NewFrameDATA([]byte("one")),
		protocol.NewFramePADDING(8),
		protocol.NewFrameDATA([]byte("two")),
		protocol.NewFrameFIN(),
	}

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	require.NoError(t, w.WriteRecord(protocol.EncodeFrames(frames)))

	decEnc, decCtr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	require.NoError(t, err)
	dr := NewDecryptedReader(&buf, aad, decEnc, decCtr)

	for _, want := range frames {
		got, err := dr.ReadFrame()
		require.NoError(t, err)
		require.Equal(t, want.Type, got.Type)
		require.Equal(t, len(want.Payload), len(got.Payload))
		if len(want.Payload) > 0 {
			require.Equal(t, want.Payload, got.Payload)
		}
	}
}

func TestMultipleRecords(t *testing.T) {
	masterKey, _ := DeriveMasterKey("multi-record-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)

	records := [][]byte{
		[]byte("record one"),
		[]byte("record two"),
		[]byte("record three"),
	}

	for _, rec := range records {
		err = w.WriteRecord(rec)
		require.NoError(t, err)
	}

	decEnc, decCtr, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)
	r := NewRecordReader(&buf, decEnc, decCtr, decAAD)

	for i, expected := range records {
		got, err := r.ReadRecord()
		require.NoError(t, err)
		require.Equal(t, expected, got, "record %d mismatch", i)
	}
}

func TestRecordTamperDetection(t *testing.T) {
	masterKey, _ := DeriveMasterKey("tamper-key")
	salt, _ := GenerateSalt()
	endpoint := "/v3/tcp"

	sk, err := NewStreamKeys(masterKey, salt, endpoint)
	require.NoError(t, err)

	enc, ctr, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	aad := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	var buf bytes.Buffer
	w := NewRecordWriter(&buf, enc, ctr, aad)
	err = w.WriteRecord([]byte("secret data"))
	require.NoError(t, err)

	raw := buf.Bytes()
	raw[len(raw)-1] ^= 0xFF

	decEnc, decCtr, err := sk.Encryptor("c2s", "bootstrap", protocol.MethodAES256GCM)
	require.NoError(t, err)
	decAAD := BuildAAD(endpoint, salt, "c2s", "bootstrap", protocol.MethodAES256GCM)

	r := NewRecordReader(bytes.NewReader(raw), decEnc, decCtr, decAAD)
	_, err = r.ReadRecord()
	require.Error(t, err, "tampered data should fail decryption")
}
