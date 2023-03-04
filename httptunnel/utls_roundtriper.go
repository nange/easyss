package httptunnel

// Ref: https://github.com/refraction-networking/utls/issues/16

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type roundTrip struct {
	helloID utls.ClientHelloID
	rootCAs *x509.CertPool

	once               sync.Once
	negotiatedProtocol string

	dialTLSContext func() (net.Conn, error)
	h1s            *http.Transport
	h2s            *http2.Transport
}

func NewRoundTrip(serverAddr string, helloID utls.ClientHelloID, timeout time.Duration, rootCAs *x509.CertPool) *roundTrip {
	if timeout == 0 {
		timeout = 10 * time.Second
	}

	hostname, port, _ := net.SplitHostPort(serverAddr)
	dialTLSContext := func() (net.Conn, error) {
		var dialConn net.Conn
		dialConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%s", hostname, port), timeout)
		if err != nil {
			return nil, err
		}

		config := &utls.Config{
			ServerName: hostname,
			RootCAs:    rootCAs,
		}
		tlsConn := utls.UClient(dialConn, config, helloID)
		if err = tlsConn.Handshake(); err != nil {
			return nil, err
		}
		return tlsConn, nil
	}

	return &roundTrip{
		helloID: helloID,
		rootCAs: rootCAs,

		dialTLSContext: dialTLSContext,
		h1s: &http.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialTLSContext()
			},
			IdleConnTimeout:       timeout,
			ResponseHeaderTimeout: timeout,
		},
		h2s: &http2.Transport{
			DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
				return dialTLSContext()
			},
			ReadIdleTimeout: timeout,
		},
	}
}

func (r *roundTrip) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "http" {
		return nil, errors.New("http request must not in utls round trip")
	}

	var err error
	r.once.Do(func() {
		var tlsConn net.Conn
		tlsConn, err = r.dialTLSContext()
		if err != nil {
			return
		}
		defer tlsConn.Close()

		r.negotiatedProtocol = tlsConn.(*utls.UConn).ConnectionState().NegotiatedProtocol
	})
	if err != nil {
		return nil, err
	}

	switch r.negotiatedProtocol {
	case http2.NextProtoTLS:
		return r.h2s.RoundTrip(req)
	default:
		return r.h1s.RoundTrip(req)
	}
}
