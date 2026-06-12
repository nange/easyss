package shaper

import (
	"bytes"
	"errors"
	"io"
	"testing"

	easycrypto "github.com/nange/easyss/v3/crypto"
	"github.com/nange/easyss/v3/protocol"
)

func TestBuildPaddingFrames(t *testing.T) {
	tests := []struct {
		name      string
		totalSize int
	}{
		{"tiny", 32},
		{"small", 256},
		{"medium", 700},
		{"large", 1600},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			frames := BuildPaddingFrames(tt.totalSize)
			if len(frames) > 1 {
				t.Fatalf("expected at most 1 padding frame, got %d", len(frames))
			}
			if len(frames) == 1 {
				if frames[0].Type != protocol.FramePADDING {
					t.Fatalf("expected PADDING frame, got %d", frames[0].Type)
				}
				if int(frames[0].Length) == 0 {
					t.Fatal("padding frame length is 0")
				}
			}
		})
	}
}

func TestBatchShaperFlushesBeforePlainRecordLimit(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-limit-test-key")
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("1234567890123456")
	endpoint := "/v3/tcp"
	sk, err := easycrypto.NewStreamKeys(masterKey, salt, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	enc, ctr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	aad := easycrypto.BuildAAD(endpoint, salt, "c2s", "session", protocol.MethodAES256GCM)

	var out bytes.Buffer
	bs := NewLight(easycrypto.NewRecordWriter(&out, enc, ctr, aad), Config{BatchWindowMS: 1000})
	payload := make([]byte, 16*1024)
	for range 4 {
		if err := bs.PushFrame(protocol.NewFrameDATA(payload)); err != nil {
			t.Fatal(err)
		}
	}
	if err := bs.Flush(); err != nil {
		t.Fatal(err)
	}

	decEnc, decCtr, err := sk.Encryptor("c2s", "session", protocol.MethodAES256GCM)
	if err != nil {
		t.Fatal(err)
	}
	rr := easycrypto.NewRecordReader(&out, decEnc, decCtr, aad)
	records := 0
	for {
		plaintext, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if len(plaintext) > protocol.MaxPlainRecordSize {
			t.Fatalf("record plaintext size %d exceeds max %d", len(plaintext), protocol.MaxPlainRecordSize)
		}
		records++
	}
	if records != 2 {
		t.Fatalf("records = %d, want 2", records)
	}
}
