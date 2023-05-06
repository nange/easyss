package bufpipe

import (
	"errors"
	"net"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util/bytespool"
)

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return "pipe" }

type connPipe struct {
	r   *PipeReader
	w   *PipeWriter
	buf []byte
}

// ConnPipe creates an asynchronous, in-memory, full duplex
// network connection; both ends implement the Conn interface.
// Reads on one end are matched with writes on the other
func ConnPipe() (net.Conn, net.Conn) {
	b1 := bytespool.Get(cipherstream.MaxCipherRelaySize)
	b2 := bytespool.Get(cipherstream.MaxCipherRelaySize)
	r1, w1 := NewBufPipe(cipherstream.MaxPayloadSize * 4)
	r2, w2 := NewBufPipe(cipherstream.MaxPayloadSize * 4)

	p1 := &connPipe{
		r:   r1,
		w:   w2,
		buf: b1,
	}
	p2 := &connPipe{
		r:   r2,
		w:   w1,
		buf: b2,
	}
	return p1, p2
}

func (*connPipe) LocalAddr() net.Addr  { return pipeAddr{} }
func (*connPipe) RemoteAddr() net.Addr { return pipeAddr{} }

func (p *connPipe) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	return n, err
}

func (p *connPipe) Write(b []byte) (int, error) {
	return p.w.Write(b)
}

func (p *connPipe) SetDeadline(t time.Time) error {
	return errors.New("unsupported SetDeadline")
}

func (p *connPipe) SetReadDeadline(t time.Time) error {
	return errors.New("unsupported SetReadDeadline")
}

func (p *connPipe) SetWriteDeadline(t time.Time) error {
	return errors.New("unsupported SetWriteDeadline")
}

func (p *connPipe) Close() error {
	defer bytespool.MustPut(p.buf)
	return p.w.Close()
}
