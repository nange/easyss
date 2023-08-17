package httptunnel

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/nange/easyss/v2/log"
)

const (
	RequestIDHeader = "X-Request-UID"
	UserAgent       = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
)

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
	left     []byte
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
	if len(l.left) > 0 {
		n = copy(b, l.left)
		if n < len(l.left) {
			l.left = l.left[n:]
		} else {
			l.left = nil
		}
		return
	}

	l.Lock()
	if err := l.checkConn(); err != nil {
		l.Unlock()
		return 0, err
	}
	if l.respBody == nil {
		if err = l.pull(); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] pull", "err", err)
			l.Unlock()
			return
		}
	}
	l.Unlock()

	dec := json.NewDecoder(l.respBody)
	var resp pullResp
	if err = dec.Decode(&resp); err == nil {
		var data []byte
		if data, err = base64.StdEncoding.DecodeString(resp.Ciphertext); err == nil {
			n = copy(b, data)
			if n < len(data) {
				l.left = data[n:]
			}
		}
	}

	if err != nil {
		log.Debug("[HTTP_TUNNEL_LOCAL] read from remote", "err", err)
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
			log.Warn("[HTTP_TUNNEL_LOCAL] push", "err", err)
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
	p := &pullParam{}
	if err := faker.FakeData(p); err != nil {
		return err
	}

	v := url.Values{}
	v.Set("mchid", strconv.FormatInt(int64(p.Mchid), 10))
	v.Set("transaction_id", p.TransactionID)
	req, err := http.NewRequest(http.MethodGet, l.serverAddr+"/pull?"+v.Encode(), nil)
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
	p := &pushPayload{}
	if err := faker.FakeData(p); err != nil {
		return err
	}
	p.Ciphertext = base64.StdEncoding.EncodeToString(data)
	payload, _ := json.Marshal(p)

	req, err := http.NewRequest(http.MethodPost, l.serverAddr+"/push", bytes.NewBuffer(payload))
	if err != nil {
		return err
	}
	req.ContentLength = int64(len(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(RequestIDHeader, l.uuid)
	req.Header.Set("User-Agent", UserAgent)

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
