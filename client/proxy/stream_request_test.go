package proxy

import (
	"testing"

	"github.com/nange/easyss/v3/config"
	"github.com/nange/easyss/v3/protocol"
)

func TestNewStreamRequestDerivesEndpointFromProto(t *testing.T) {
	t.Parallel()

	cases := []struct {
		proto    protocol.Proto
		endpoint string
	}{
		{proto: protocol.ProtoTCP, endpoint: config.EndpointTCP},
		{proto: protocol.ProtoUDP, endpoint: config.EndpointUDP},
		{proto: protocol.ProtoICMP, endpoint: config.EndpointICMP},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			t.Parallel()

			req := newStreamRequest(tc.proto, "example.com:443", protocol.MethodAES256GCM)
			if req.endpoint != tc.endpoint {
				t.Fatalf("endpoint = %q, want %q", req.endpoint, tc.endpoint)
			}
		})
	}

	if req := newStreamRequest(protocol.Proto(0), "example.com:443", protocol.MethodAES256GCM); req.endpoint != "" {
		t.Errorf("unknown proto endpoint = %q, want empty", req.endpoint)
	}
}

func TestStreamRequestConstructorsKeepEndpointAndProtoPaired(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		req  streamRequest
	}{
		{name: "tcp", req: tcpStreamRequest("example.com:443", protocol.MethodAES256GCM)},
		{name: "udp", req: udpStreamRequest("8.8.8.8:53", protocol.MethodAES256GCM)},
		{name: "icmp", req: icmpStreamRequest("example.com", protocol.MethodAES256GCM)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := protocol.Handshake{Proto: tc.req.proto}
			if !h.MatchesEndpoint(tc.req.endpoint) {
				t.Fatalf("endpoint %q does not match proto %d", tc.req.endpoint, tc.req.proto)
			}
		})
	}
}

func TestStreamRequestBuilders(t *testing.T) {
	t.Parallel()

	base := tcpStreamRequest("example.com:443", protocol.MethodAES256GCM)
	req := base.withFrames(protocol.NewFrameDATA([]byte("hello"))).withBatchWindow(1)

	if len(base.frames) != 0 || base.batchWindowMS != 0 {
		t.Fatalf("builders must not mutate the receiver: frames=%d batch=%d", len(base.frames), base.batchWindowMS)
	}
	if got, want := req.firstPayloadBytes(), len("hello"); got != want {
		t.Errorf("firstPayloadBytes = %d, want %d", got, want)
	}
	if len(req.frames) != 1 || string(req.frames[0].Payload) != "hello" {
		t.Errorf("frames = %v, want one DATA frame with payload %q", req.frames, "hello")
	}
	if req.batchWindowMS != 1 {
		t.Errorf("batchWindowMS = %d, want 1", req.batchWindowMS)
	}
	if got := (streamRequest{}).firstPayloadBytes(); got != 0 {
		t.Errorf("empty request firstPayloadBytes = %d, want 0", got)
	}
}
