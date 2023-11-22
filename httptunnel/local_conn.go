package httptunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/go-faker/faker/v4"
	"github.com/gofrs/uuid/v5"
	"github.com/imroc/req/v3"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/nange/easyss/v2/util/netpipe"
)

const (
	RequestIDHeader = "X-Request-UID"
)

type LocalConn struct {
	uuid       string
	serverAddr string
	conn       net.Conn
	conn2      net.Conn

	client   *req.Client
	respBody io.ReadCloser
	left     []byte
}

func NewLocalConn(client *req.Client, serverAddr string) (net.Conn, error) {
	if client == nil {
		return nil, errors.New("http outbound client is nil")
	}

	id, err := uuid.NewV7()
	if err != nil {
		return nil, err
	}
	conn, conn2 := netpipe.Pipe(2 * cipherstream.MaxPayloadSize)
	lc := &LocalConn{
		uuid:       id.String(),
		serverAddr: serverAddr,
		conn:       conn,
		conn2:      conn2,
		client:     client,
	}

	go lc.Push()
	go lc.Pull()

	return conn, nil
}

func (l *LocalConn) Pull() {
	if l.respBody == nil {
		if err := l.pull(); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] pull", "err", err, "uuid", l.uuid)
			return
		}
	}
	defer l.PullClose()

	dec := json.NewDecoder(l.respBody)
	var resp pullResp

	for {
		if err := dec.Decode(&resp); err != nil {
			if !errors.Is(err, io.EOF) && !strings.Contains(err.Error(), "connection reset by peer") {
				log.Warn("[HTTP_TUNNEL_LOCAL] decode response", "err", err, "uuid", l.uuid)
			}
			if resp.Payload == "" {
				break
			}
		}

		data, err := base64.StdEncoding.DecodeString(resp.Payload)
		if err != nil {
			log.Error("[HTTP_TUNNEL_LOCAL] decode cipher text", "err", err, "uuid", l.uuid)
			break
		}
		resp.Payload = ""
		if _, err := l.conn2.Write(data); err != nil {
			log.Error("[HTTP_TUNNEL_LOCAL] write text", "err", err, "uuid", l.uuid)
			break
		}
	}
	log.Debug("[HTTP_TUNNEL_LOCAL] Pull completed...", "uuid", l.uuid)
}

func (l *LocalConn) Push() {
	defer l.PushClose()

	if err := l.push(); err != nil {
		if !errors.Is(err, io.EOF) {
			log.Error("[HTTP_TUNNEL_LOCAL] push", "err", err, "uuid", l.uuid)
		}
	}

	log.Debug("[HTTP_TUNNEL_LOCAL] Push completed...", "uuid", l.uuid)
}

func (l *LocalConn) PullClose() {
	if l.respBody != nil {
		_ = l.respBody.Close()
	}
	_ = l.conn2.Close()
}

func (l *LocalConn) PushClose() {
	_ = l.conn.Close()
}

func (l *LocalConn) pull() error {
	p := &pullParam{}
	if err := faker.FakeData(p); err != nil {
		return err
	}

	resp, err := l.client.R().
		SetQueryParam("account_id", p.AccountID).
		SetQueryParam("transaction_id", p.TransactionID).
		SetQueryParam("access_token", p.AccessToken).
		SetHeader(RequestIDHeader, l.uuid).
		SetHeader("Accept-Encoding", "gzip").
		Get(l.serverAddr + "/pull")
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

func (l *LocalConn) push() error {
	resp, err := l.client.R().
		SetHeader("Content-Type", "application/json").
		SetHeader("Transfer-Encoding", "chunked").
		SetHeader(RequestIDHeader, l.uuid).
		SetHeader("Accept-Encoding", "gzip").
		SetHeader("Content-Encoding", "gzip").
		SetBody(l).
		Post(l.serverAddr + "/push")
	if err != nil {
		return err
	}

	body, err := resp.ToBytes()
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("status code:%v, body:%v", resp.StatusCode, string(body))
	}

	return nil
}

// Read implements io.Reader
func (l *LocalConn) Read(b []byte) (int, error) {
	if len(l.left) > 0 {
		cn := copy(b, l.left)
		if cn < len(l.left) {
			l.left = l.left[cn:]
		} else {
			l.left = nil
		}
		return cn, nil
	}

	buf := bytespool.Get(cipherstream.MaxPayloadSize)
	defer bytespool.MustPut(buf)

	var payload []byte
	n, err := l.conn2.Read(buf)
	if n > 0 {
		p := &pushPayload{}
		_ = faker.FakeData(p)
		p.Payload = base64.StdEncoding.EncodeToString(buf[:n])
		payload, _ = json.Marshal(p)
	}

	cn := copy(b, payload)
	if cn < len(payload) {
		l.left = payload[cn:]
	}

	return cn, err
}
