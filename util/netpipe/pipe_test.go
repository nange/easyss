package netpipe

import (
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPipe(t *testing.T) {
	p1, p2 := Pipe(11)
	n, err := p1.Write([]byte("hello hello hello"))
	assert.Equal(t, 0, n)
	assert.Equal(t, err, ErrExceedMaxSize)
	n, err = p2.Write([]byte("hello hello hello"))
	assert.Equal(t, 0, n)
	assert.Equal(t, err, ErrExceedMaxSize)

	n, err = p1.Write([]byte("hello"))
	assert.Equal(t, 5, n)
	assert.Nil(t, err)

	n, err = p1.Write([]byte("hello2"))
	assert.Equal(t, 6, n)
	assert.Nil(t, err)
	n, err = p2.Write([]byte("hello"))
	assert.Equal(t, 5, n)
	assert.Nil(t, err)
	n, err = p2.Write([]byte("hello2"))
	assert.Equal(t, 6, n)
	assert.Nil(t, err)

	b := make([]byte, 128)
	n, err = p1.Read(b)
	assert.Equal(t, 11, n)
	assert.Nil(t, err)
	assert.Equal(t, []byte("hellohello2"), b[:n])
	n, err = p2.Read(b)
	assert.Equal(t, 11, n)
	assert.Nil(t, err)
	assert.Equal(t, []byte("hellohello2"), b[:n])

	n, err = p1.Write([]byte("hello3"))
	assert.Equal(t, 6, n)
	assert.Nil(t, err)
	assert.Nil(t, p1.Close())

	n, err = p2.Read(b)
	assert.Equal(t, 6, n)
	assert.Equal(t, ErrPipeClosed, err)
	n, err = p2.Read(b)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}
