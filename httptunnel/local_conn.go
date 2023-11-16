package httptunnel

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"

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
	pushed     chan struct{}

	client   *req.Client
	respBody io.ReadCloser
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
		conn:       conn2,
		pushed:     make(chan struct{}, 1),
		client:     client,
	}

	go lc.Push()
	go lc.Pull()

	return conn, nil
}

func (l *LocalConn) Pull() {
	if l.respBody == nil {
		<-l.pushed
		if err := l.pull(); err != nil {
			log.Warn("[HTTP_TUNNEL_LOCAL] pull", "err", err, "uuid", l.uuid)
			return
		}
	}
	defer l.Close()

	dec := json.NewDecoder(l.respBody)
	var resp pullResp

	for {
		if err := dec.Decode(&resp); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warn("[HTTP_TUNNEL_LOCAL] decode response", "err", err, "uuid", l.uuid)
			}
			if resp.Ciphertext == "" {
				break
			}
		}

		data, err := base64.StdEncoding.DecodeString(resp.Ciphertext)
		if err != nil {
			log.Error("[HTTP_TUNNEL_LOCAL] decode cipher text", "err", err, "uuid", l.uuid)
			break
		}
		resp.Ciphertext = ""
		if _, err := l.conn.Write(data); err != nil {
			log.Error("[HTTP_TUNNEL_LOCAL] write text", "err", err, "uuid", l.uuid)
			break
		}
	}
	log.Info("[HTTP_TUNNEL_LOCAL] Pull completed...", "uuid", l.uuid)
}

func (l *LocalConn) Push() {
	buf := bytespool.Get(cipherstream.MaxPayloadSize)
	defer bytespool.MustPut(buf)

	for {
		n, err := l.conn.Read(buf)
		if er := l.push(buf[:n]); er != nil {
			err = errors.Join(err, er)
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Error("[HTTP_TUNNEL_LOCAL] push", "err", err, "uuid", l.uuid)
			}
			break
		}
		// notify pull goroutine
		select {
		case l.pushed <- struct{}{}:
		default:
		}
	}

	log.Info("[HTTP_TUNNEL_LOCAL] Push completed...", "uuid", l.uuid)
}

func (l *LocalConn) Close() {
	if l.respBody != nil {
		_ = l.respBody.Close()
	}
	_ = l.conn.Close()
}

func (l *LocalConn) pull() error {
	p := &pullParam{}
	if err := faker.FakeData(p); err != nil {
		return err
	}

	resp, err := l.client.R().
		SetQueryParam("mchid", strconv.FormatInt(int64(p.Mchid), 10)).
		SetQueryParam("transaction_id", p.TransactionID).
		SetHeader(RequestIDHeader, l.uuid).
		//SetHeader("Accept-Encoding", "gzip").
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

func (l *LocalConn) push(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	p := &pushPayload{}
	if err := faker.FakeData(p); err != nil {
		return err
	}
	p.Ciphertext = base64.StdEncoding.EncodeToString(data)
	payload, _ := json.Marshal(p)

	resp, err := l.client.R().
		SetHeader("Content-Length", strconv.FormatInt(int64(len(payload)), 10)).
		SetHeader("Content-Type", "application/json").
		SetHeader(RequestIDHeader, l.uuid).
		//SetHeader("Accept-Encoding", "gzip").
		SetBodyBytes(payload).
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
