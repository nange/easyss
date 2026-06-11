package protocol

import (
	"bytes"
	"testing"
)

func TestFrameEncodeDecode(t *testing.T) {
	payload := []byte("hello world")
	f := NewFrameDATA(payload)

	var buf bytes.Buffer
	if err := WriteFrame(&buf, f); err != nil {
		t.Fatalf("WriteFrame: %v", err)
	}

	got, err := ReadFrame(&buf)
	if err != nil {
		t.Fatalf("ReadFrame: %v", err)
	}

	if got.Type != FrameDATA {
		t.Errorf("Type: got %d, want %d", got.Type, FrameDATA)
	}
	if got.Length != uint16(len(payload)) {
		t.Errorf("Length: got %d, want %d", got.Length, len(payload))
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Errorf("Payload: got %v, want %v", got.Payload, payload)
	}
}

func TestFrameHANDSHAKE(t *testing.T) {
	hs := Handshake{
		Version: Version3,
		Proto:   ProtoTCP,
		Method:  MethodAES256GCM,
		Target:  "example.com:443",
	}

	f := NewFrameHANDSHAKE(hs)
	if f.Type != FrameHANDSHAKE {
		t.Errorf("Type: got %d, want %d", f.Type, FrameHANDSHAKE)
	}

	decoded, err := DecodeHandshake(f.Payload)
	if err != nil {
		t.Fatalf("DecodeHandshake: %v", err)
	}

	if decoded.Version != hs.Version || decoded.Proto != hs.Proto || decoded.Method != hs.Method || decoded.Target != hs.Target {
		t.Errorf("handshake mismatch: got %+v, want %+v", decoded, hs)
	}
}

func TestHandshakeMatchesEndpoint(t *testing.T) {
	hs := Handshake{Proto: ProtoTCP}
	if !hs.MatchesEndpoint("/v3/tcp") {
		t.Error("expected match for /v3/tcp")
	}
	if hs.MatchesEndpoint("/v3/udp") {
		t.Error("expected no match for /v3/udp")
	}
}

func TestEncodeFrames(t *testing.T) {
	frames := []Frame{
		NewFrameDATA([]byte("hello")),
		NewFramePADDING(10),
		NewFrameFIN(),
	}
	plaintext := EncodeFrames(frames)

	reader := bytes.NewReader(plaintext)

	var decoded []Frame
	for reader.Len() > 0 {
		f, err := ReadFrame(reader)
		if err != nil {
			t.Fatalf("ReadFrame: %v", err)
		}
		decoded = append(decoded, f)
	}

	if len(decoded) != 3 {
		t.Fatalf("got %d frames, want 3", len(decoded))
	}
	if decoded[0].Type != FrameDATA {
		t.Errorf("frame 0 type: got %d, want %d", decoded[0].Type, FrameDATA)
	}
	if decoded[1].Type != FramePADDING {
		t.Errorf("frame 1 type: got %d, want %d", decoded[1].Type, FramePADDING)
	}
	if decoded[2].Type != FrameFIN {
		t.Errorf("frame 2 type: got %d, want %d", decoded[2].Type, FrameFIN)
	}
}

func TestDATAGRAMFrame(t *testing.T) {
	payload := make([]byte, 1500)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	f := NewFrameDATAGRAM(payload)
	if f.Type != FrameDATAGRAM {
		t.Errorf("Type: got %d, want %d", f.Type, FrameDATAGRAM)
	}
	if int(f.Length) != 1500 {
		t.Errorf("Length: got %d, want 1500", f.Length)
	}
}
