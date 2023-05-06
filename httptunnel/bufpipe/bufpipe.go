package bufpipe

// Ref: https://github.com/acomagu/bufpipe

import (
	"bytes"
	"errors"
	"io"
	"sync"

	"github.com/nange/easyss/v2/util/bytespool"
)

const defaultMaxBufSize = 16 * 1024 // 16K

// ErrClosedPipe is the error used for read or write operations on a closed pipe.
var ErrClosedPipe = errors.New("bufpipe: read/write on closed pipe")

type pipe struct {
	maxSize    int
	cond       *sync.Cond
	buf        *bytes.Buffer
	written    int
	rerr, werr error
}

// A PipeReader is the read half of a pipe.
type PipeReader struct {
	*pipe
}

// A PipeWriter is the write half of a pipe.
type PipeWriter struct {
	*pipe
}

// NewBufPipe creates an async pipe using buf as its initial contents. It can be
// used to connect code expecting an io.Reader with code expecting an io.Writer.
//
// It is safe to call Read and Write in parallel with each other or with Close.
// Parallel calls to Read and parallel calls to Write are also safe: the
// individual calls will be gated sequentially.
func NewBufPipe(maxSize int) (*PipeReader, *PipeWriter) {
	if maxSize == 0 {
		maxSize = defaultMaxBufSize
	}
	buf := bytespool.GetBuffer()
	p := &pipe{
		maxSize: maxSize,
		buf:     buf,
		cond:    sync.NewCond(new(sync.Mutex)),
	}
	return &PipeReader{
			pipe: p,
		}, &PipeWriter{
			pipe: p,
		}
}

// Read implements the standard Read interface: it reads data from the pipe,
// reading from the internal buffer, otherwise blocking until a writer arrives
// or the write end is closed. If the write end is closed with an error, that
// error is returned as err; otherwise err is io.EOF.
func (r *PipeReader) Read(data []byte) (int, error) {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	if r.rerr != nil {
		if r.buf != nil {
			bytespool.PutBuffer(r.buf)
			r.buf = nil
		}
		return 0, r.rerr
	}

RETRY:
	n, err := r.buf.Read(data)
	// If not closed and no read, wait for writing.
	if err == io.EOF && r.rerr == nil && n == 0 {
		r.written = 0
		r.cond.Signal()
		r.cond.Wait()
		goto RETRY
	}

	defer r.cond.Signal()
	if err == io.EOF {
		if r.buf != nil {
			bytespool.PutBuffer(r.buf)
			r.buf = nil
		}
		r.written = 0
		return n, r.rerr
	}
	return n, err
}

// Close closes the reader; subsequent writes from the write half of the pipe
// will return error ErrClosedPipe.
func (r *PipeReader) Close() error {
	return r.CloseWithError(nil)
}

// CloseWithError closes the reader; subsequent writes to the write half of the
// pipe will return the error err.
func (r *PipeReader) CloseWithError(err error) error {
	r.cond.L.Lock()
	defer r.cond.L.Unlock()

	if err == nil {
		err = ErrClosedPipe
	}
	r.werr = err
	if r.rerr == nil {
		r.rerr = err
	}
	return nil
}

// Write implements the standard Write interface: it writes data to the internal
// buffer. If the read end is closed with an error, that err is returned as err;
// otherwise err is ErrClosedPipe.
func (w *PipeWriter) Write(data []byte) (int, error) {
	w.cond.L.Lock()
	defer w.cond.L.Unlock()

	var n int
	for {
		if w.werr != nil {
			return n, w.werr
		}
		if w.maxSize == w.written {
			w.cond.Wait()
			if w.werr != nil {
				return 0, w.werr
			}
		}

		if len(data) <= (w.maxSize - w.written) {
			n, _ = w.buf.Write(data)
			w.written += n
			w.cond.Signal()
			return n, nil
		} else {
			n, _ = w.buf.Write(data[:w.maxSize-w.written])
			data = data[w.maxSize-w.written:]
			w.written += n
			w.cond.Signal()
			w.cond.Wait()
		}
	}
}

// Close closes the writer; subsequent reads from the read half of the pipe will
// return io.EOF once the internal buffer get empty.
func (w *PipeWriter) Close() error {
	return w.CloseWithError(nil)
}

// CloseWithError closes the writer; subsequent reads from the read half of the pipe will
// return err once the internal buffer get empty.
func (w *PipeWriter) CloseWithError(err error) error {
	w.cond.L.Lock()
	defer w.cond.L.Unlock()

	if err == nil {
		err = io.EOF
	}
	if w.rerr == nil {
		w.rerr = err
	}
	w.cond.Broadcast()
	return nil
}
