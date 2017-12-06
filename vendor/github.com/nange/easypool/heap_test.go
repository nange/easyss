package easypool

import (
	"log"
	"net"
	"testing"
	"time"
)

var (
	InitialCap = 5
	MaxCap     = 30
	MaxIdle    = 5
	network    = "tcp"
	address    = "127.0.0.1:7777"
	factory    = func() (net.Conn, error) { return net.Dial(network, address) }
)

func init() {
	// used for factory function
	go simpleTCPServer()
	time.Sleep(time.Second) // wait until tcp server has been settled
}

func TestNew(t *testing.T) {
	_, err := newHeapPool()
	if err != nil {
		t.Errorf("New error: %v", err)
	}
}

func TestPool(t *testing.T) {
	p, _ := newHeapPool()

	conn, err := p.Get()
	if err != nil {
		t.Errorf("Get error: %s", err)
	}

	_, ok := conn.(*PoolConn)
	if !ok {
		t.Errorf("Conn is not of type poolConn")
	}

	if err := conn.Close(); err != nil {
		t.Errorf("Pool Conn close error:%v", err)
	}

	if p.Len() != InitialCap {
		t.Errorf("Pool size is invalid, size:%v", p.Len())
	}

	p.Close()

	_, err = p.Get()
	if err != ErrClosed {
		t.Errorf("After pool closed, Get() should return ErrClosed error")
	}
}

func TestPriorityQueue(t *testing.T) {
	p, _ := newHeapPool()
	conn1, err := p.Get()
	if err != nil {
		t.Errorf("Get error: %s", err)
	}

	conn2, err := p.Get()
	if err != nil {
		t.Errorf("Get error: %s", err)
	}

	pc1 := conn1.(*PoolConn)
	pc2 := conn2.(*PoolConn)
	if pc1.updatedtime.Sub(pc2.updatedtime) > 0 {
		t.Errorf("priority is invalid, older conn should first out")
	}
	pc1.Close()
	pc2.Close()

	p.Close()
}

func TestPoolConcurrent(t *testing.T) {
	p, _ := newHeapPool()
	for i := 0; i < MaxCap+10; i++ {
		conn, err := p.Get()
		if err != nil {
			t.Errorf("Get error: %s", err)
		}
		go func(conn net.Conn) {
			time.Sleep(time.Second)
			conn.Close()
		}(conn)
	}

	time.Sleep(5 * time.Second)
	if p.Len() != MaxCap {
		t.Errorf("Pool length should equals:, but get:%v", MaxCap, p.Len())
	}

	time.Sleep(30 * time.Second)
	if p.Len() != MaxIdle {
		t.Errorf("Pool length should equals MaxIdle, but get:%v", p.Len())
	}

	time.Sleep(30 * time.Second)
	if p.Len() != 0 {
		t.Errorf("Pool length should equals 0, but get:%v", p.Len())
	}

	p.Close()
}

func TestPoolConcurrent2(t *testing.T) {
	p, _ := newHeapPool()
	for i := 0; i < MaxCap; i++ {
		conn, err := p.Get()
		if err != nil {
			t.Errorf("Get error: %s", err)
		}
		go func(conn net.Conn, i int) {
			time.Sleep(time.Second)
			if i >= MaxCap-10 {
				conn.(*PoolConn).MarkUnusable()
				if !conn.(*PoolConn).IsUnusable() {
					t.Errorf("after mark unusable, IsUnusable() should return true")
				}
			}
			conn.Close()
		}(conn, i)
	}

	time.Sleep(5 * time.Second)
	if p.Len() != MaxCap-10 {
		t.Errorf("Pool length should equals:%v, but get:%v", MaxCap-10, p.Len())
	}

	p.Close()
}

func newHeapPool() (Pool, error) {
	return NewHeapPool(&PoolConfig{
		InitialCap:  InitialCap,
		MaxCap:      MaxCap,
		MaxIdle:     MaxIdle,
		Idletime:    10 * time.Second,
		MaxLifetime: time.Minute,
		Factory:     factory,
	})
}

func simpleTCPServer() {
	l, err := net.Listen(network, address)
	if err != nil {
		log.Fatal(err)
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Fatal(err)
		}

		go func() {
			buffer := make([]byte, 256)
			conn.Read(buffer)
		}()
	}
}
