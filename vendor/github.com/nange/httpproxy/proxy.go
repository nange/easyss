package httpproxy

import (
	"crypto/tls"
	"net/http"
	"sync/atomic"
	"net/url"
)

// Proxy defines parameters for running an HTTP Proxy. It implements
// http.Handler interface for ListenAndServe function. If you need, you must
// set Proxy struct before handling requests.
type Proxy struct {
	// Session number of last proxy request.
	SessionNo int64

	// RoundTripper interface to obtain remote response.
	// By default, it uses &http.Transport{}.
	Rt http.RoundTripper

	// Certificate key pair.
	Ca tls.Certificate

	// User data to use free.
	UserData interface{}

	// Error callback.
	OnError func(ctx *Context, where string, err *Error, opErr error)

	// Accept callback. It greets proxy request like ServeHTTP function of
	// http.Handler.
	// If it returns true, stops processing proxy request.
	OnAccept func(ctx *Context, w http.ResponseWriter, r *http.Request) bool

	// Auth callback. If you need authentication, set this callback.
	// If it returns true, authentication succeeded.
	OnAuth func(ctx *Context, authType string, user string, pass string) bool

	// Connect callback. It sets connect action and new host.
	// If len(newhost) > 0, host changes.
	OnConnect func(ctx *Context, host string) (ConnectAction ConnectAction,
		newHost string)

	// Forward callback. It forward the underline hijack connection
	OnForward func(ctx *Context, host string) error

	// Request callback. It greets remote request.
	// If it returns non-nil response, stops processing remote request.
	OnRequest func(ctx *Context, req *http.Request) (resp *http.Response)

	// Response callback. It greets remote response.
	// Remote response sends after this callback.
	OnResponse func(ctx *Context, req *http.Request, resp *http.Response)

	// If ConnectAction is ConnectMitm, it sets chunked to Transfer-Encoding.
	// By default, true.
	MitmChunked bool

	// HTTP Authentication type. If it's not specified (""), uses "Basic".
	// By default, "".
	AuthType string

	signer *CaSigner
}

// NewProxy returns a new Proxy has default CA certificate and key.
func NewProxy() (*Proxy, error) {
	return NewProxyCert(nil, nil)
}

// NewProxyCert returns a new Proxy given CA certificate and key.
func NewProxyCert(caCert, caKey []byte) (*Proxy, error) {
	prx := &Proxy{
		Rt: &http.Transport{TLSClientConfig: &tls.Config{},
			Proxy: func(request *http.Request) (*url.URL, error) {
				return url.Parse("socks5://127.0.0.1:1080")
			}},
		MitmChunked: true,
		signer:      NewCaSignerCache(1024),
	}
	prx.signer.Ca = &prx.Ca
	if caCert == nil {
		caCert = DefaultCaCert
	}
	if caKey == nil {
		caKey = DefaultCaKey
	}
	var err error
	prx.Ca, err = tls.X509KeyPair(caCert, caKey)
	if err != nil {
		return nil, err
	}
	return prx, nil
}

// ServeHTTP implements http.Handler.
func (prx *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := &Context{Prx: prx, SessionNo: atomic.AddInt64(&prx.SessionNo, 1)}

	defer func() {
		rec := recover()
		if rec != nil {
			if err, ok := rec.(error); ok && prx.OnError != nil {
				prx.OnError(ctx, "ServeHTTP", ErrPanic, err)
			}
			panic(rec)
		}
	}()

	if ctx.doAccept(w, r) {
		return
	}

	if ctx.doAuth(w, r) {
		return
	}
	r.Header.Del("Proxy-Connection")
	r.Header.Del("Proxy-Authenticate")
	r.Header.Del("Proxy-Authorization")

	if b := ctx.doConnect(w, r); b {
		return
	}

	for {
		var w2 = w
		var r2 = r
		var cyclic = false
		switch ctx.ConnectAction {
		case ConnectMitm:
			if prx.MitmChunked {
				cyclic = true
			}
			w2, r2 = ctx.doMitm()
		}
		if w2 == nil || r2 == nil {
			break
		}
		//r.Header.Del("Accept-Encoding")
		//r.Header.Del("Connection")
		ctx.SubSessionNo++
		if b, err := ctx.doRequest(w2, r2); err != nil {
			break
		} else {
			if b {
				if !cyclic {
					break
				} else {
					continue
				}
			}
		}
		if err := ctx.doResponse(w2, r2); err != nil || !cyclic {
			break
		}
	}

	if ctx.hijTLSConn != nil {
		ctx.hijTLSConn.Close()
	}
}
