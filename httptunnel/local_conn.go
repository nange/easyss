package httptunnel

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gofrs/uuid/v5"
	log "github.com/sirupsen/logrus"
)

const RequestIDHeader = "X-Request-UID"

var _ net.Conn = (*LocalConn)(nil)

type localConnAddr struct{}

func (localConnAddr) Network() string { return "http outbound" }
func (localConnAddr) String() string  { return "http outbound" }

type timeoutError struct{}

func (e timeoutError) Error() string   { return "i/o timeout" }
func (e timeoutError) Timeout() bool   { return true }
func (e timeoutError) Temporary() bool { return true }

var _ net.Error = (*timeoutError)(nil)

type LocalConn struct {
	uuid       string
	serverAddr string

	// once for protecting done
	once sync.Once
	done chan struct{}
	sync.Mutex
	timeout         *time.Timer
	settingDeadline chan struct{}
	expired         chan struct{}

	client   *http.Client
	respBody io.ReadCloser
}

func NewLocalConn(client *http.Client, serverAddr string) (*LocalConn, error) {
	if client == nil {
		return nil, errors.New("http outbound client is nil")
	}
	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	return &LocalConn{
		uuid:            id.String(),
		serverAddr:      serverAddr,
		done:            make(chan struct{}),
		settingDeadline: make(chan struct{}),
		expired:         make(chan struct{}),
		client:          client,
	}, nil
}

func (l *LocalConn) Read(b []byte) (n int, err error) {
	l.Lock()
	if err := l.checkConn(); err != nil {
		l.Unlock()
		return 0, err
	}
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
		log.Debugf("[HTTP_TUNNEL_LOACAL] read from remote:%v", err)
		if strings.Contains(err.Error(), "http2: server sent GOAWAY and closed the connection") {
			// Ref: https://github.com/golang/go/issues/18639
			err = io.EOF
		} else if strings.Contains(err.Error(), "response body closed") {
			// In LocalConn.SetDeadline func, we'll close the response body
			select {
			case <-l.done:
			default:
				err = timeoutError{}
			}
		}
	}

	return
}

func (l *LocalConn) Write(b []byte) (n int, err error) {
	l.Lock()
	if err := l.checkConn(); err != nil {
		l.Unlock()
		return 0, err
	}
	l.Unlock()
	if err := l.push(b); err != nil {
		if !errors.Is(err, io.EOF) {
			log.Warnf("[HTTP_TUNNEL_LOACAL] push:%v", err)
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

// SetDeadline if the deadline time fired, then the LocalConn can't be used anymore
func (l *LocalConn) SetDeadline(t time.Time) error {
	l.Lock()
	defer l.Unlock()
	if err := l.checkConn(); err != nil {
		return err
	}
	if l.timeout == nil {
		l.timeout = time.NewTimer(time.Until(t))
		go func() {
			defer l.timeout.Stop()
			for {
				select {
				case <-l.settingDeadline:
					// wait for setting deadline to be done
					<-l.settingDeadline
				case <-l.timeout.C:
					l.Lock()
					if l.respBody != nil {
						l.respBody.Close()
					}
					close(l.expired)
					l.Unlock()
					return
				case <-l.done:
					return
				}
			}
		}()
	} else {
		// write to settingDeadline chan to prevent others goroutine receives from `l.timeout.C` chan
		l.settingDeadline <- struct{}{}
		if !l.timeout.Stop() {
			select {
			case <-l.timeout.C:
			default:
			}
		}
		if !t.IsZero() {
			l.timeout.Reset(time.Until(t))
		}
		// notify others goroutine to continue
		l.settingDeadline <- struct{}{}
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
	req.Header.Set(RequestIDHeader, l.uuid)

	resp, err := l.client.Do(req)
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
	req.Header.Set(RequestIDHeader, l.uuid)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/110.0.0.0 Safari/537.36")

	resp, err := l.client.Do(req)
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

func (l *LocalConn) checkConn() error {
	select {
	case <-l.done:
		return errors.New("LocalConn was closed")
	case <-l.expired:
		return timeoutError{}
	default:
		return nil
	}
}
