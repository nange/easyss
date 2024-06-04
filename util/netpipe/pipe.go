package netpipe

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/smallnest/ringbuffer"
)

var _ net.Conn = (*pipe)(nil) // ensure to implements net.Conn

// Pipe is buffered version of net.Pipe. Reads
// will block until data is available.
type pipe struct {
	buf  *ringbuffer.RingBuffer
	back []byte
	cond sync.Cond
	mu   sync.Mutex

	maxSize       int
	rLate         bool
	wLate         bool
	closed        bool
	err           error
	readDeadline  time.Time
	writeDeadline time.Time
	remoteAddr    net.Addr
	localAddr     net.Addr
}

var ErrDeadline = fmt.Errorf("pipe deadline exceeded")
var ErrPipeClosed = fmt.Errorf("pipe closed")
var ErrExceedMaxSize = fmt.Errorf("exceed max size")

// Read waits until data is available and copies bytes
// from the buffer into p.
func (p *pipe) Read(b []byte) (n int, err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.rLate {
		return 0, ErrDeadline
	}

	if !p.readDeadline.IsZero() {
		now := time.Now()
		dur := p.readDeadline.Sub(now)
		if dur <= 0 {
			p.rLate = true
			return 0, ErrDeadline
		}
		nextReadDone := make(chan struct{})
		defer close(nextReadDone)
		go func(dur time.Duration) {
			timer := time.NewTimer(dur)
			defer timer.Stop()
			select {
			case <-timer.C:
				p.cond.L.Lock()
				p.rLate = true
				p.cond.L.Unlock()
				p.cond.Broadcast()
			case <-nextReadDone:
			}
		}(dur)
	}

	defer p.cond.Broadcast()

	for p.buf.Length() == 0 && !p.closed && !p.rLate {
		p.cond.Broadcast()
		p.cond.Wait()
	}

	if p.rLate {
		return 0, ErrDeadline
	}

	return p.buf.Read(b)
}

// Write copies bytes from p into the buffer and wakes a reader.
// It is an error to write more data than the buffer can hold.
func (p *pipe) Write(b []byte) (n int, err error) {
	if len(b) > p.maxSize {
		return 0, ErrExceedMaxSize
	}

	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.wLate {
		return 0, ErrDeadline
	}

	if !p.writeDeadline.IsZero() {
		now := time.Now()
		dur := p.writeDeadline.Sub(now)
		if dur <= 0 {
			p.wLate = true
			return 0, ErrDeadline
		}
		nextWriteDone := make(chan struct{})
		defer close(nextWriteDone)
		go func(dur time.Duration) {
			timer := time.NewTimer(dur)
			defer timer.Stop()
			select {
			case <-timer.C:
				p.cond.L.Lock()
				p.wLate = true
				p.cond.L.Unlock()
				p.cond.Broadcast()
			case <-nextWriteDone:
			}
		}(dur)
	}
	defer p.cond.Broadcast()

	for p.buf.Free() < len(b) && !p.closed && !p.wLate {
		p.cond.Broadcast()
		p.cond.Wait()
	}

	if p.wLate {
		return 0, ErrDeadline
	}

	return p.buf.Write(b)
}

func (p *pipe) Close() error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	p.closed = true
	p.buf.CloseWithError(ErrPipeClosed)
	p.cond.Broadcast()
	bytespool.MustPut(p.back)
	return nil
}

func (p *pipe) CloseWrite() error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	p.closed = true
	p.buf.CloseWriter()
	p.cond.Broadcast()
	return nil
}

// Pipe technically implements the net.Conn interface

func (p *pipe) LocalAddr() net.Addr {
	if p.localAddr != nil {
		return p.localAddr
	}
	return addr{}
}
func (p *pipe) RemoteAddr() net.Addr {
	if p.remoteAddr != nil {
		return p.remoteAddr
	}
	return addr{}
}

type addr struct{}

func (a addr) String() string  { return "memory:0" }
func (a addr) Network() string { return "pipe" }

// SetDeadline implements the net.Conn method
func (p *pipe) SetDeadline(t time.Time) error {
	err := p.SetReadDeadline(t)
	err2 := p.SetWriteDeadline(t)
	if err != nil {
		return err
	}
	return err2
}

// SetWriteDeadline implements the net.Conn method
func (p *pipe) SetWriteDeadline(t time.Time) error {
	p.cond.L.Lock()
	p.writeDeadline = t
	p.wLate = false
	p.cond.L.Unlock()
	return nil
}

// SetReadDeadline implements the net.Conn method
func (p *pipe) SetReadDeadline(t time.Time) error {
	p.cond.L.Lock()
	p.readDeadline = t
	p.rLate = false
	p.cond.L.Unlock()
	return nil
}
