package httptunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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
	}, nil
}

func (l *LocalConn) Read(b []byte) (n int, err error) {
	if l.respBody == nil {
		if err = l.pull(); err != nil {
			log.Warnf("[HTTP_TUNNEL_LOACAL] pull:%v", err)
			return
		}
	}
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
		log.Errorf("[HTTP_TUNNEL_LOACAL] push:%v", err)
		return 0, err
	}

	return len(b), nil
}

func (l *LocalConn) Close() error {
	return l.respBody.Close()
}

func (l *LocalConn) LocalAddr() net.Addr {
	return localConnAddr{}
}

func (l *LocalConn) RemoteAddr() net.Addr {
	return localConnAddr{}
}

func (l *LocalConn) SetDeadline(t time.Time) error {
	panic("must be unreachable")
}

func (l *LocalConn) SetReadDeadline(t time.Time) error {
	panic("must be unreachable")
}

func (l *LocalConn) SetWriteDeadline(t time.Time) error {
	panic("must be unreachable")
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

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status code:%v, body:%v", resp.StatusCode, string(body))
	}

	return nil
}
