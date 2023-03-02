package httptunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	log "github.com/sirupsen/logrus"
)

var localClient = &http.Client{}

var _ net.Conn = (*LocalConn)(nil)

type localConnAddr struct{}

func (localConnAddr) Network() string { return "http outbound" }
func (localConnAddr) String() string  { return "http outbound" }

type LocalConn struct {
	uuid       string
	serverAddr string

	// once for protecting done
	once sync.Once
	done chan struct{}
	sync.Mutex
	timeout *time.Timer

	respBody io.ReadCloser
}

func NewLocalConn(serverAddr string) (*LocalConn, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	return &LocalConn{
		uuid:       id.String(),
		serverAddr: serverAddr,
		done:       make(chan struct{}),
	}, nil
}

func (l *LocalConn) Read(b []byte) (n int, err error) {
	l.Lock()
	if l.respBody == nil {
		if err = l.pull(); err != nil {
			log.Warnf("[HTTP_TUNNEL_LOACAL] pull:%v", err)
			l.Unlock()
			return
		}
	}
	l.Unlock()
	n, err = l.respBody.Read(b)
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Warnf("[HTTP_TUNNEL_LOACAL] read from remote:%v", err)
		}
	}

	return
}

func (l *LocalConn) Write(b []byte) (n int, err error) {
	if err := l.push(b); err != nil {
		if !errors.Is(err, io.EOF) {
			log.Errorf("[HTTP_TUNNEL_LOACAL] push:%v", err)
		}
		return 0, err
	}

	return len(b), nil
}

func (l *LocalConn) Close() error {
	l.Lock()
	defer l.Unlock()
	l.once.Do(func() {
		close(l.done)
	})
	if l.respBody != nil {
		return l.respBody.Close()
	}
	return nil
}

func (l *LocalConn) LocalAddr() net.Addr {
	return localConnAddr{}
}

func (l *LocalConn) RemoteAddr() net.Addr {
	return localConnAddr{}
}

func (l *LocalConn) SetDeadline(t time.Time) error {
	l.Lock()
	defer l.Unlock()
	if l.timeout == nil {
		l.timeout = time.NewTimer(t.Sub(time.Now()))
		go func() {
			defer l.timeout.Stop()
			for {
				select {
				case <-l.timeout.C:
					l.Lock()
					if l.respBody != nil {
						l.respBody.Close()
					}
					l.Unlock()
				case <-l.done:
					return
				}
			}
		}()
	} else {
		if !l.timeout.Stop() {
			<-l.timeout.C
		}
		if !t.IsZero() {
			l.timeout.Reset(t.Sub(time.Now()))
		}
	}

	return nil
}

func (l *LocalConn) SetReadDeadline(t time.Time) error {
	return l.SetDeadline(t)
}

func (l *LocalConn) SetWriteDeadline(t time.Time) error {
	return l.SetDeadline(t)
}

func (l *LocalConn) pull() error {
	req, err := http.NewRequest(http.MethodGet, l.serverAddr+"/pull", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Request-ID", l.uuid)

	resp, err := localClient.Do(req)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("pull response status code:%v, body:%v", resp.StatusCode, string(body))
	}

	l.respBody = resp.Body
	return nil
}

func (l *LocalConn) push(data []byte) error {
	req, err := http.NewRequest(http.MethodPost, l.serverAddr+"/push", bytes.NewBuffer(data))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(data))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("X-Request-ID", l.uuid)

	resp, err := localClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status code:%v, body:%v", resp.StatusCode, string(body))
	}

	return nil
}
