package httptunnel

import (
	"errors"
	"net"
	"time"

	"github.com/acomagu/bufpipe"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util/bytespool"
)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type pipe struct {
	r   *bufpipe.PipeReader
	w   *bufpipe.PipeWriter
	buf []byte
}

// Pipe creates an asynchronous, in-memory, full duplex
// network connection; both ends implement the Conn interface.
// Reads on one end are matched with writes on the other
func Pipe() (net.Conn, net.Conn) {
	b1 := bytespool.Get(cipherstream.MaxCipherRelaySize)
	b2 := bytespool.Get(cipherstream.MaxCipherRelaySize)
	r1, w1 := bufpipe.New(b1[:0])
	r2, w2 := bufpipe.New(b2[:0])

	p1 := &pipe{
		r:   r1,
		w:   w2,
		buf: b1,
	}
	p2 := &pipe{
		r:   r2,
		w:   w1,
		buf: b2,
	}
	return p1, p2
}

func (*pipe) LocalAddr() net.Addr  { return pipeAddr{} }
func (*pipe) RemoteAddr() net.Addr { return pipeAddr{} }

func (p *pipe) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	return n, err
}

func (p *pipe) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *pipe) SetDeadline(t time.Time) error {
	return errors.New("unsupported SetDeadline")
}

func (p *pipe) SetReadDeadline(t time.Time) error {
	return errors.New("unsupported SetReadDeadline")
}

func (p *pipe) SetWriteDeadline(t time.Time) error {
	return errors.New("unsupported SetWriteDeadline")
}

func (p *pipe) Close() error {
	defer bytespool.MustPut(p.buf)
	return p.w.Close()
}
