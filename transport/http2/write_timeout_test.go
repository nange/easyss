package http2

import (
	"testing"
	"time"

	"github.com/nange/easyss/v3/config"
)

// 写记录在 shaper 的写锁内做网络写：没有写超时，一条阻塞的连接会把同连接上的
// 所有流以及关闭路径一起钉住。
func TestBuildTransportBoundsWriteStalls(t *testing.T) {
	timeouts := config.Timeouts{Base: 42 * time.Second}.Normalize()

	tr := buildTransport(&transportSlot{}, &slotTransport{}, nil, timeouts, nil)
	if tr.HTTP2 == nil {
		t.Fatal("HTTP2 config must be set")
	}
	if got := tr.HTTP2.WriteByteTimeout; got != timeouts.Base {
		t.Fatalf("WriteByteTimeout = %v, want %v", got, timeouts.Base)
	}
}
