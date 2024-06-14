package httptunnel

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/klauspost/compress/gzhttp"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util/bytespool"
	"github.com/nange/easyss/v2/util/netpipe"
	"github.com/segmentio/encoding/json"
)

const RelayBufferSize = cipherstream.MaxCipherRelaySize

type Server struct {
	addr    string
	timeout time.Duration

	sync.Mutex
	connMap     map[string][]net.Conn
	connCh      chan net.Conn
	closing     chan struct{}
	pullWaiting map[string]chan struct{}

	tlsConfig *tls.Config
	server    *http.Server
}

func NewServer(addr string, timeout time.Duration, tlsConfig *tls.Config) *Server {
	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: timeout,
	}

	return &Server{
		addr:        addr,
		timeout:     timeout,
		connMap:     make(map[string][]net.Conn, 256),
		connCh:      make(chan net.Conn, 1),
		closing:     make(chan struct{}, 1),
		pullWaiting: make(map[string]chan struct{}, 256),
		tlsConfig:   tlsConfig,
		server:      server,
	}
}

func (s *Server) Listen() {
	s.handler()

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		log.Error("[HTTP_TUNNEL_SERVER] Listen", "err", err)
		os.Exit(1)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	log.Info("[HTTP_TUNNEL_SERVER] listen http tunnel at", "addr", s.addr)
	log.Warn("[HTTP_TUNNEL_SERVER] http serve:", "err", s.server.Serve(ln))
}

func (s *Server) Close() error {
	s.Lock()
	defer s.Unlock()
	close(s.closing)

	return s.server.Close()
}

func (s *Server) Accept() (net.Conn, error) {
	select {
	case conn := <-s.connCh:
		return conn, nil
	case <-s.closing:
		return nil, errors.New("server is closed")
	}
}

func (s *Server) handler() {
	http.Handle("GET /pull", gzhttp.GzipHandler(http.HandlerFunc(s.pull)))
	http.Handle("POST /push", gzhttp.GzipHandler(http.HandlerFunc(s.push)))
}

// pullWait wait push request to arrive
func (s *Server) pullWait(reqID string) error {
	s.Lock()
	if _, ok := s.connMap[reqID]; ok {
		s.Unlock()
		return nil
	}
	ch := make(chan struct{}, 1)
	s.pullWaiting[reqID] = ch
	s.Unlock()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ch:
		return nil
	case <-timer.C:
		return errors.New("timeout for pull waiting")
	}
}

func (s *Server) pull(w http.ResponseWriter, r *http.Request) {
	reqID := r.URL.Query().Get(RequestIDQuery)
	if reqID == "" {
		// compatible with old versions
		reqID = r.Header.Get(RequestIDHeader)
	}
	if reqID == "" {
		log.Warn("[HTTP_TUNNEL_SERVER] pull uuid is empty")
		writeNotFoundError(w)
		return
	}
	if err := s.pullWait(reqID); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] pull uuid not found", "uuid", reqID)
		writeNotFoundError(w)
		return
	}

	s.Lock()
	conns := s.connMap[reqID]
	s.Unlock()
	log.Debug("[HTTP_TUNNEL_SERVER] pull", "uuid", reqID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")
	w.Header().Set("Content-Encoding", "gzip")

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	var n int
	var p = &pullResp{}
	for {
		_ = conns[0].SetReadDeadline(time.Now().Add(s.timeout))
		n, err = conns[0].Read(buf)
		if n > 0 {
			_ = faker.FakeData(p)
			p.Payload = base64.StdEncoding.EncodeToString(buf[:n])
			b, _ := json.Marshal(p)
			if _, er := w.Write(b); er != nil {
				err = errors.Join(err, er)
				log.Warn("[HTTP_TUNNEL_SERVER] response write", "err", er)
				break
			}
			_, _ = w.Write([]byte("\n"))
			p.Payload = ""
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, netpipe.ErrPipeClosed) {
		log.Warn("[HTTP_TUNNEL_SERVER] read from conn", "err", err)
	}

	s.pullClose(reqID)
	log.Info("[HTTP_TUNNEL_SERVER] Pull completed...", "uuid", reqID)
}

func (s *Server) notifyPull(reqID string) {
	ch, ok := s.pullWaiting[reqID]
	if !ok {
		return
	}
	ch <- struct{}{}

	s.pullWaiting[reqID] = nil
	delete(s.pullWaiting, reqID)
}

func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	buf := bytespool.GetBuffer()
	defer bytespool.PutBuffer(buf)

	_, err := io.Copy(buf, r.Body)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] read request body", "err", err, "body", buf.String())
		writeServiceUnavailableError(w, "read request body:"+err.Error())
		return
	}

	p := &pushPayload{}
	if err := json.Unmarshal(buf.Bytes(), p); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] unmarshal request body", "err", err, "body", buf.String())
		writeServiceUnavailableError(w, "unmarshal request body:"+err.Error())
		return
	}

	reqID := p.RequestUID
	if reqID == "" {
		// compatible with old versions
		reqID = r.Header.Get(RequestIDHeader)
	}
	if reqID == "" {
		log.Warn("[HTTP_TUNNEL_SERVER] push uuid is empty")
		writeNotFoundError(w)
		return
	}
	log.Debug("[HTTP_TUNNEL_SERVER] push", "uuid", reqID)

	addr, _ := net.ResolveTCPAddr("tcp", r.RemoteAddr)
	s.Lock()
	conns, ok := s.connMap[reqID]
	if !ok {
		conn1, conn2 := netpipe.Pipe(2*cipherstream.MaxPayloadSize, addr)
		conns = []net.Conn{conn1, conn2}
		s.connMap[reqID] = conns
		s.connCh <- conn2
	}
	s.notifyPull(reqID)
	s.Unlock()

	if p.Payload == "" {
		// client end push
		_ = conns[0].(interface{ CloseWrite() error }).CloseWrite()
		return
	}
	cipher, err := base64.StdEncoding.DecodeString(p.Payload)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] decode cipher", "err", err)
		writeServiceUnavailableError(w, "decode cipher:"+err.Error())
		return
	}

	if _, err = conns[0].Write(cipher); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write local", "err", err)
		writeServiceUnavailableError(w, "write local:"+err.Error())
		return
	}

	writeSuccess(w)
}

func (s *Server) pullClose(reqID string) {
	s.Lock()
	defer s.Unlock()

	if conns, ok := s.connMap[reqID]; ok {
		_ = conns[0].Close()
	}

	s.connMap[reqID] = nil
	delete(s.connMap, reqID)
}

func writeNotFoundError(w http.ResponseWriter) {
	w.Header().Set("Content-Encoding", "gzip")
	http.Error(w, "404 NOT FOUND", http.StatusNotFound)
}

func writeServiceUnavailableError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Encoding", "gzip")
	http.Error(w, msg, http.StatusServiceUnavailable)
}

func writeSuccess(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Encoding", "gzip")
	if _, err := w.Write([]byte(`{"code":"SUCCESS", "message":"PUSH SUCCESS"}`)); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write success", "err", err)
	}
}
