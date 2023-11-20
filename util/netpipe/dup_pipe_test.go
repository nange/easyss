package netpipe

import (
	"fmt"
	"io"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestDupPipe_Read_Write(t *testing.T) {
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
	assert.Nil(t, err)
	n, err = p2.Read(b)
	assert.Equal(t, 0, n)
	assert.Equal(t, io.EOF, err)
}

func TestDupPipe_TimeWait(t *testing.T) {
	p1, p2 := Pipe(11)
	go func() {
		time.Sleep(time.Second)
		_, _ = p1.Write([]byte("hello"))
		_, _ = p2.Write([]byte("hello2"))
	}()

	b := make([]byte, 10)
	n, err := p1.Read(b)
	assert.Nil(t, err)
	assert.Equal(t, 6, n)

	n, err = p2.Read(b)
	assert.Nil(t, err)
	assert.Equal(t, 5, n)
}

func TestDupPip_ConReadWrite(t *testing.T) {
	p1, p2 := Pipe(64)
	count1 := 0
	go func() {
		for i := 0; i < 100000; i++ {
			str := fmt.Sprintf("hello%d", i)
			n, err := p1.Write([]byte(str))
			assert.Nil(t, err)
			count1 += n
		}
		assert.Nil(t, p1.Close())
	}()

	b := make([]byte, 64)
	count2 := 0
	for {
		n, err := p2.Read(b)
		count2 += n
		if err != nil {
			assert.Equal(t, io.EOF, err)
			break
		}
	}
	assert.Equal(t, count1, count2)
}
