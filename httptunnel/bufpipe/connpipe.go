package bufpipe

import (
	"errors"
	"net"
	"sync"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type timeoutError struct{}

func (e timeoutError) Error() string   { return "i/o timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

var _ net.Error = (*timeoutError)(nil)

type connPipe struct {
	r *PipeReader
	w *PipeWriter

	// once for protecting done
	once sync.Once
	done chan struct{}
	sync.Mutex
	timeout         *time.Timer
	settingDeadline chan struct{}
	expired         chan struct{}
}

// ConnPipe creates an asynchronous, in-memory, full duplex
// network connection; both ends implement the Conn interface.
// Reads on one end are matched with writes on the other
func ConnPipe() (net.Conn, net.Conn) {
	r1, w1 := NewBufPipe(cipherstream.MaxPayloadSize * 4)
	r2, w2 := NewBufPipe(cipherstream.MaxPayloadSize * 4)

	p1 := &connPipe{
		r:               r1,
		w:               w2,
		done:            make(chan struct{}),
		settingDeadline: make(chan struct{}),
		expired:         make(chan struct{}),
	}
	p2 := &connPipe{
		r:               r2,
		w:               w1,
		done:            make(chan struct{}),
		settingDeadline: make(chan struct{}),
		expired:         make(chan struct{}),
	}
	return p1, p2
}

func (*connPipe) LocalAddr() net.Addr  { return pipeAddr{} }
func (*connPipe) RemoteAddr() net.Addr { return pipeAddr{} }

func (p *connPipe) Read(b []byte) (int, error) {
	p.Lock()
	if err := p.checkConn(); err != nil {
		p.Unlock()
		return 0, err
	}
	p.Unlock()

	return p.r.Read(b)
}

func (p *connPipe) Write(b []byte) (int, error) {
	p.Lock()
	if err := p.checkConn(); err != nil {
		p.Unlock()
		return 0, err
	}
	p.Unlock()

	return p.w.Write(b)
}

func (p *connPipe) SetDeadline(t time.Time) error {
	p.Lock()
	defer p.Unlock()
	if err := p.checkConn(); err != nil {
		return err
	}
	if p.timeout == nil {
		p.timeout = time.NewTimer(time.Until(t))
		go func() {
			defer p.timeout.Stop()
			for {
				select {
				case <-p.settingDeadline:
					// wait for setting deadline to be done
					<-p.settingDeadline
				case <-p.timeout.C:
					p.Lock()
					if p.r != nil {
						p.r.Close()
					}
					if p.w != nil {
						p.w.Close()
					}
					close(p.expired)
					p.Unlock()
					return
				case <-p.done:
					return
				}
			}
		}()
	} else {
		// write to settingDeadline chan to prevent others goroutine receives from `l.timeout.C` chan
		p.settingDeadline <- struct{}{}
		if !p.timeout.Stop() {
			select {
			case <-p.timeout.C:
			default:
			}
		}
		if !t.IsZero() {
			p.timeout.Reset(time.Until(t))
		}
		// notify others goroutine to continue
		p.settingDeadline <- struct{}{}
	}

	return nil
}

func (p *connPipe) SetReadDeadline(t time.Time) error {
	return p.SetDeadline(t)
}

func (p *connPipe) SetWriteDeadline(t time.Time) error {
	return p.SetDeadline(t)
}

func (p *connPipe) Close() error {
	p.Lock()
	defer p.Unlock()
	p.once.Do(func() {
		close(p.done)
	})

	return p.w.Close()
}

func (p *connPipe) checkConn() error {
	select {
	case <-p.done:
		return errors.New("connPipe was closed")
	case <-p.expired:
		return timeoutError{}
	default:
		return nil
	}
}
