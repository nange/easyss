package netpipe

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/smallnest/ringbuffer"
)

var _ net.Conn = (*pipe)(nil) // ensure to implements net.Conn

// Pipe is buffered version of net.Pipe. Reads
// will block until data is available.
type pipe struct {
	buf    *ringbuffer.RingBuffer
	back   []byte
	rdChan chan struct{}
	wdChan chan struct{}
	cond   sync.Cond
	mu     sync.Mutex

	maxSize    int
	rLate      bool
	wLate      bool
	rdID       string
	wdID       string
	closed     bool
	closing    chan struct{}
	remoteAddr net.Addr
	localAddr  net.Addr
}

var ErrReadDeadline = fmt.Errorf("pipe read deadline exceeded")
var ErrWriteDeadline = fmt.Errorf("pipe write deadline exceeded")
var ErrPipeClosed = fmt.Errorf("pipe closed")
var ErrExceedMaxSize = fmt.Errorf("exceed max size")

// Read waits until data is available and copies bytes
// from the buffer into p.
func (p *pipe) Read(b []byte) (n int, err error) {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.rLate {
		return 0, ErrReadDeadline
	}

	defer p.cond.Broadcast()

	for p.buf.Length() == 0 && !p.closed && !p.rLate {
		p.cond.Broadcast()
		p.cond.Wait()
	}

	if p.rLate {
		return 0, ErrReadDeadline
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
		return 0, ErrWriteDeadline
	}

	defer p.cond.Broadcast()

	for p.buf.Free() < len(b) && !p.closed && !p.wLate {
		p.cond.Broadcast()
		p.cond.Wait()
	}

	if p.wLate {
		return 0, ErrWriteDeadline
	}

	return p.buf.Write(b)
}

func (p *pipe) Close() error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if !p.closed {
		p.closed = true
		close(p.closing)
	}

	p.buf.CloseWithError(ErrPipeClosed)
	p.cond.Broadcast()
	if len(p.back) > 0 {
		bytespool.MustPut(p.back)
		p.back = nil
	}

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
	return errors.Join(err, err2)
}

// SetWriteDeadline implements the net.Conn method
func (p *pipe) SetWriteDeadline(t time.Time) error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.closed {
		return ErrPipeClosed
	}

	uid, err := uuid.NewV7()
	if err != nil {
		return err
	}
	wdID := uid.String()
	p.wdID = wdID

	// Let the previous goroutine exit, if it exists.
	select {
	case p.wdChan <- struct{}{}:
	default:
	}

	if t.IsZero() || t.After(time.Now()) {
		p.wLate = false
	} else {
		p.wLate = true
		p.cond.Broadcast()
		return nil
	}

	if !t.IsZero() {
		go func() {
			timer := time.NewTimer(time.Until(t))
			defer timer.Stop()

			select {
			case <-timer.C:
				p.cond.L.Lock()
				if p.wdID == wdID {
					p.wLate = true
					p.cond.Broadcast()
				}
				p.cond.L.Unlock()
			case <-p.wdChan:
			case <-p.closing:
			}
		}()
	}

	return nil
}

// SetReadDeadline implements the net.Conn method
func (p *pipe) SetReadDeadline(t time.Time) error {
	p.cond.L.Lock()
	defer p.cond.L.Unlock()

	if p.closed {
		return ErrPipeClosed
	}

	uid, err := uuid.NewV7()
	if err != nil {
		return err
	}
	rdID := uid.String()
	p.rdID = rdID

	// Let the previous goroutine exit, if it exists.
	select {
	case p.rdChan <- struct{}{}:
	default:
	}

	if t.IsZero() || t.After(time.Now()) {
		p.rLate = false
	} else {
		p.rLate = true
		p.cond.Broadcast()
		return nil
	}

	if !t.IsZero() {
		go func() {
			timer := time.NewTimer(time.Until(t))
			defer timer.Stop()

			select {
			case <-timer.C:
				p.cond.L.Lock()
				if p.rdID == rdID {
					p.rLate = true
					p.cond.Broadcast()
				}
				p.cond.L.Unlock()
			case <-p.rdChan:
			case <-p.closing:
			}
		}()
	}

	return nil
}
