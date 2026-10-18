package shaper

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"
	"time"

	easycrypto "github.com/nange/easyss/v3/crypto"
)

// TestBatchShaperWritesRecordsInFlushOrder 固定"记录按 flush 换出顺序写出"：
// flushAndWrite 在 bs.mu 下换出缓冲，随后才去抢 writeMu；并发的 flush 因此
// 可能后换出、先抢到写锁。若写出不按序号排序，定时器冲刷与数据冲刷重叠时，
// 后一段 DATA 会先落到线上，TCP 字节流被静默重排。
//
// 这里直接让序号 1 先到、序号 0 后到：前者必须等后者写完，否则顺序就反了。
func TestBatchShaperWritesRecordsInFlushOrder(t *testing.T) {
	masterKey, err := easycrypto.DeriveMasterKey("batch-flush-order")
	if err != nil {
		t.Fatal(err)
	}
	sk, err := easycrypto.NewStreamKeys(masterKey, []byte("1234567890123456"), "/v3/tcp")
	if err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	sh := New(newTestWriter(t, sk, &out), Config{BatchWindowMS: 1})
	bs, ok := sh.(*batchShaper)
	if !ok {
		t.Fatalf("New returned %T, want *batchShaper", sh)
	}
	defer bs.Close() //nolint:errcheck

	second := make(chan error, 1)
	started := make(chan struct{})
	go func() {
		close(started)
		second <- bs.writeRecordInOrder(1, []byte("second"), false)
	}()
	<-started

	// 序号 1 已经提交，但序号 0 还没写：它必须阻塞，而不能抢先落盘。
	select {
	case err := <-second:
		t.Fatalf("sequence 1 was written before sequence 0: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	if err := bs.writeRecordInOrder(0, []byte("first"), false); err != nil {
		t.Fatalf("write sequence 0: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("write sequence 1: %v", err)
	}

	rr := newTestReader(t, sk, bytes.NewReader(out.Bytes()))
	var got []string
	for {
		data, err := rr.ReadRecord()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read record: %v", err)
		}
		got = append(got, string(data))
	}
	if want := []string{"first", "second"}; !slices.Equal(got, want) {
		t.Fatalf("record order = %v, want %v", got, want)
	}
}
