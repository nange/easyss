package easyss

import (
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/txthinking/socks5"
)

func TestEasyss_UDPHandle(t *testing.T) {
	c, err := socks5.NewClient("127.0.0.1:4080", "", "", 0, 60)
	assert.Nil(t, err)

	conn, err := c.Dial("udp", "8.8.8.8:53")
	assert.Nil(t, err)
	defer conn.Close()

	b, err := hex.DecodeString("0001010000010000000000000a74787468696e6b696e6703636f6d0000010001")
	assert.Nil(t, err)

	for i := 0; i < 2; i++ {
		_, err = conn.Write(b)
		assert.Nil(t, err)
		time.Sleep(time.Second)

		b1 := make([]byte, 2048)
		n, err := conn.Read(b1)
		assert.Nil(t, err)

		b1 = b1[:n]
		b1 = b1[len(b)-4:]
		time.Sleep(1 * time.Second)
	}

	conn.Close()
	fmt.Println("client closed, sleep 100s")
	time.Sleep(10 * time.Second)

}
