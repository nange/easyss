package netpipe

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/smallnest/ringbuffer"
)

var _ net.Conn = (*pipe)(nil) // ensure to implements net.Conn

// Pipe is buffered version of net.Pipe. Reads
// will block until data is available.
type pipe struct {
	buf  *ringbuffer.RingBuffer
	cond sync.Cond
	mu   sync.Mutex

	maxSize       int
	rLate         bool
	wLate         bool
	closed        bool
	err           error
	readDeadline  time.Time
	writeDeadline time.Time
}

var ErrDeadline = fmt.Errorf("pipe deadline exceeded")
var ErrPipeClosed = fmt.Errorf("pipe closed")
var ErrExceedMaxSize = fmt.Errorf("exceed max size")

// Read waits until data is available and copies bytes
// from the buffer into p.
func (p *pipe) Read(b []byte) (n int, err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if !p.readDeadline.IsZero() {
		now := time.Now()
		dur := p.readDeadline.Sub(now)
		if dur <= 0 {
			return 0, ErrDeadline
		}
		nextReadDone := make(chan struct{})
		defer close(nextReadDone)
		go func(dur time.Duration) {
			select {
			case <-time.After(dur):
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
		err = ErrDeadline
	} else {
		n, err = p.buf.Read(b)
		if p.buf.IsEmpty() && p.closed && n == 0 {
			err = io.EOF
		}
	}

	return
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
	if p.closed {
		return 0, ErrPipeClosed
	}

	if !p.writeDeadline.IsZero() {
		now := time.Now()
		dur := p.writeDeadline.Sub(now)
		if dur <= 0 {
			return 0, ErrDeadline
		}
		nextWriteDone := make(chan struct{})
		defer close(nextWriteDone)
		go func(dur time.Duration) {
			select {
			case <-time.After(dur):
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
	p.SetErrorAndClose(ErrPipeClosed)
	return nil
}

func (p *pipe) SetErrorAndClose(err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()
	defer p.cond.Broadcast()
	if !p.closed {
		p.closed = true
		p.err = err
	}
}

// Pipe technically fullfills the net.Conn interface

func (p *pipe) LocalAddr() net.Addr  { return addr{} }
func (p *pipe) RemoteAddr() net.Addr { return addr{} }

type addr struct{}

func (a addr) String() string  { return "memory.pipe:0" }
func (a addr) Network() string { return "in-process-internal" }

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
