package netpipe

import (
	"bytes"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

const testTimeout = 3 * time.Second

// TestWriteIsBuffered 固定对端不读时写入立刻进入缓冲并返回（net.Pipe 会一直阻塞）。
func TestWriteIsBuffered(t *testing.T) {
	a, b := Pipe(256 << 10)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	payload := bytes.Repeat([]byte("x"), 200<<10)
	done := make(chan error, 1)
	go func() {
		_, err := a.Write(payload)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
	case <-time.After(testTimeout):
		t.Fatal("Write blocked while nobody was reading: the pipe is not buffered")
	}

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch after buffered write")
	}
}

// TestWriteLargerThanBufferCompletes 固定写入大于缓冲时等待空间并写完，而不是报错
// （net.Conn 语义：单次写入不限制大小）。
func TestWriteLargerThanBufferCompletes(t *testing.T) {
	const size = 4 << 10
	a, b := Pipe(size)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	payload := bytes.Repeat([]byte("payload-"), 4*size/8) // 4 倍缓冲
	var wg sync.WaitGroup
	wg.Add(1)
	var wrote int
	var werr error
	go func() {
		defer wg.Done()
		wrote, werr = a.Write(payload)
	}()

	buf := make([]byte, 512)
	var got []byte
	for len(got) < len(payload) {
		n, err := b.Read(buf)
		got = append(got, buf[:n]...)
		if err != nil {
			t.Fatalf("Read after %d bytes: %v", len(got), err)
		}
	}
	wg.Wait()

	if werr != nil || wrote != len(payload) {
		t.Fatalf("Write = (%d, %v), want (%d, nil)", wrote, werr, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("payload mismatch")
	}
}

// TestReadDeadlineErrorAndReuse 固定超时返回 os.ErrDeadlineExceeded（且满足
// net.Error.Timeout()）以及超时后连接仍可用：标准库与中继都按前者判断。
func TestReadDeadlineErrorAndReuse(t *testing.T) {
	a, b := Pipe(4096)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	if err := a.SetReadDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	_, err := a.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read after deadline = %v, want os.ErrDeadlineExceeded", err)
	}
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("Read error %v does not satisfy net.Error with Timeout() == true", err)
	}

	// deadline 是绝对的、滞留的：不清理就会一直超时（net.Conn 的语义）。
	if _, err := a.Read(make([]byte, 16)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("second Read = %v, want os.ErrDeadlineExceeded (the deadline must stay in effect)", err)
	}

	// 清掉 deadline 之后必须能继续用（超时不得毒化连接）。
	if err := a.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() { _, _ = b.Write([]byte("x")) }()
	if _, err := a.Read(make([]byte, 16)); err != nil {
		t.Fatalf("Read after clearing the deadline: %v", err)
	}
}

// TestPastDeadlineInterruptsBlockedRead 固定 net.Conn 的标准取消手法：用"设成过去
// 的 deadline"立刻打断已经阻塞的 Read。
func TestPastDeadlineInterruptsBlockedRead(t *testing.T) {
	a, b := Pipe(4096)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	done := make(chan error, 1)
	go func() {
		_, err := a.Read(make([]byte, 16))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if err := a.SetReadDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked Read woke with %v, want os.ErrDeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("blocked Read was interrupted only after %v", elapsed)
		}
	case <-time.After(testTimeout):
		t.Fatal("blocked Read was not interrupted by a past deadline")
	}
}

// TestPastDeadlineInterruptsBlockedWrite 对称地固定写侧：缓冲写满后的阻塞写也必须
// 能被 past deadline 打断。
func TestPastDeadlineInterruptsBlockedWrite(t *testing.T) {
	a, b := Pipe(4096)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	if _, err := a.Write(make([]byte, 4096)); err != nil { // 填满
		t.Fatalf("fill: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := a.Write(make([]byte, 4096))
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)

	start := time.Now()
	if err := a.SetWriteDeadline(time.Now().Add(-time.Hour)); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("blocked Write woke with %v, want os.ErrDeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("blocked Write was interrupted only after %v", elapsed)
		}
	case <-time.After(testTimeout):
		t.Fatal("blocked Write was not interrupted by a past deadline")
	}
}

// TestDeadlineExtensionDoesNotFireEarly 固定"deadline 被推迟后不得按旧值超时"：
// 定时器到点与 deadline 被改写可能同时发生，等待循环必须重新判断。
func TestDeadlineExtensionDoesNotFireEarly(t *testing.T) {
	a, b := Pipe(4096)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	if err := a.SetReadDeadline(time.Now().Add(120 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(60 * time.Millisecond)
		_ = a.SetReadDeadline(time.Now().Add(5 * time.Second)) // 在旧 deadline 到点前推迟
		time.Sleep(120 * time.Millisecond)                     // 旧 deadline 之后才送来数据
		_, _ = b.Write([]byte("late"))
	}()

	start := time.Now()
	buf := make([]byte, 16)
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read = %v after %v, want the extended deadline to be honored", err, time.Since(start))
	}
	if string(buf[:n]) != "late" {
		t.Fatalf("Read = %q, want %q", buf[:n], "late")
	}
}

// TestCloseSemantics 固定四个方向的关闭语义（与 net.Pipe 对齐）以及幂等性。
func TestCloseSemantics(t *testing.T) {
	a, b := Pipe(4096)

	if err := a.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := a.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}

	if _, err := b.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Errorf("peer Read after close = %v, want io.EOF", err)
	}
	if _, err := b.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("peer Write after close = %v, want io.ErrClosedPipe", err)
	}
	if _, err := a.Write([]byte("x")); err == nil {
		t.Error("Write on a closed conn succeeded")
	}
	if _, err := a.Read(make([]byte, 8)); err == nil {
		t.Error("Read on a closed conn succeeded")
	}
	_ = b.Close() //nolint:errcheck
}

// TestCloseDeliversBufferedDataFirst 固定"关闭前写入的数据不会被丢掉"：对端应当先
// 读到全部数据，再读到 EOF。
func TestCloseDeliversBufferedDataFirst(t *testing.T) {
	a, b := Pipe(4096)
	payload := []byte("buffered before close")
	if _, err := a.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	_ = a.Close()   //nolint:errcheck
	defer b.Close() //nolint:errcheck

	got := make([]byte, len(payload))
	n, err := io.ReadFull(b, got)
	if err != nil {
		t.Fatalf("ReadFull: %v (n=%d)", err, n)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	if _, err := b.Read(make([]byte, 8)); !errors.Is(err, io.EOF) {
		t.Fatalf("Read after draining = %v, want io.EOF", err)
	}
}

// TestCloseUnblocksBothSides 固定关闭能唤醒所有阻塞中的操作——隧道断开时 DERP 客户端
// 就是靠这个醒过来的。
func TestCloseUnblocksBothSides(t *testing.T) {
	t.Run("blocked read", func(t *testing.T) {
		a, b := Pipe(4096)
		done := make(chan error, 1)
		go func() {
			_, err := b.Read(make([]byte, 8))
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		_ = a.Close() //nolint:errcheck
		select {
		case err := <-done:
			if !errors.Is(err, io.EOF) {
				t.Fatalf("woke with %v, want io.EOF", err)
			}
		case <-time.After(testTimeout):
			t.Fatal("Close did not unblock the peer's blocked Read")
		}
		_ = b.Close() //nolint:errcheck
	})

	t.Run("blocked write", func(t *testing.T) {
		a, b := Pipe(1024)
		if _, err := a.Write(make([]byte, 1024)); err != nil { // 填满
			t.Fatalf("fill: %v", err)
		}
		done := make(chan error, 1)
		go func() {
			_, err := a.Write(make([]byte, 1024))
			done <- err
		}()
		time.Sleep(50 * time.Millisecond)
		_ = b.Close() //nolint:errcheck
		select {
		case err := <-done:
			if !errors.Is(err, io.ErrClosedPipe) {
				t.Fatalf("woke with %v, want io.ErrClosedPipe", err)
			}
		case <-time.After(testTimeout):
			t.Fatal("Close did not unblock the peer's blocked Write")
		}
		_ = a.Close() //nolint:errcheck
	})
}

// TestConcurrentThroughput 用一个远大于缓冲的传输量同时压读写两侧（并逐字节校验），
// 是"丢唤醒 / 丢数据 / 数据错位"这类并发缺陷的回归。
func TestConcurrentThroughput(t *testing.T) {
	const total = 4 << 20
	a, b := Pipe(32 << 10)
	defer a.Close() //nolint:errcheck
	defer b.Close() //nolint:errcheck

	payload := make([]byte, total)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	var wg sync.WaitGroup
	wg.Go(func() {
		if n, err := a.Write(payload); err != nil || n != total {
			t.Errorf("Write = (%d, %v), want (%d, nil)", n, err, total)
		}
	})

	got := make([]byte, total)
	if _, err := io.ReadFull(b, got); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	wg.Wait()
	if !bytes.Equal(got, payload) {
		t.Fatal("transferred payload mismatch")
	}
}
