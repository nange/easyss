package httptunnel

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
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
)

const RelayBufferSize = cipherstream.MaxCipherRelaySize

type Server struct {
	addr string

	sync.Mutex
	connMap map[string]*ServerConn
	connCh  chan *ServerConn
	closing chan struct{}

	tlsConfig *tls.Config
	server    *http.Server
}

func NewServer(addr string, timeout time.Duration, tlsConfig *tls.Config) *Server {
	server := &http.Server{
		Addr:              addr,
		Handler:           http.DefaultServeMux,
		ReadHeaderTimeout: timeout,
		IdleTimeout:       timeout,
	}

	return &Server{
		addr:      addr,
		connMap:   make(map[string]*ServerConn, 128),
		connCh:    make(chan *ServerConn, 1),
		closing:   make(chan struct{}, 1),
		tlsConfig: tlsConfig,
		server:    server,
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
	http.Handle("/pull", gzhttp.GzipHandler(http.HandlerFunc(s.pull)))
	http.Handle("/push", gzhttp.GzipHandler(http.HandlerFunc(s.push)))
}

func (s *Server) pull(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeNotFoundError(w)
		return
	}

	reqID := r.Header.Get(RequestIDHeader)
	s.Lock()
	conn, ok := s.connMap[reqID]
	s.Unlock()
	if !ok {
		log.Warn("[HTTP_TUNNEL_SERVER] pull uuid not found", "uuid", reqID)
		writeNotFoundError(w)
		return
	}
	log.Debug("[HTTP_TUNNEL_SERVER] pull", "uuid", reqID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	for {
		n, err := conn.ReadLocal(buf)
		if n > 0 {
			p := &pullResp{}
			if err := faker.FakeData(p); err != nil {
				log.Warn("[HTTP_TUNNEL_SERVER] fake data", "err", err)
				writeServiceUnavailableError(w, "fake data:"+err.Error())
				return
			}
			p.Ciphertext = base64.StdEncoding.EncodeToString(buf[:n])

			b, _ := json.Marshal(p)
			if _, err = w.Write(b); err != nil {
				log.Warn("[HTTP_TUNNEL_SERVER] response write", "err", err)
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warn("[HTTP_TUNNEL_SERVER] read from conn", "err", err)
			}
			return
		}
	}
}

func (s *Server) push(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeNotFoundError(w)
		return
	}

	reqID := r.Header.Get(RequestIDHeader)
	if reqID == "" {
		log.Warn("[HTTP_TUNNEL_SERVER] push uuid is empty")
		writeNotFoundError(w)
		return
	}
	log.Debug("[HTTP_TUNNEL_SERVER] push", "uuid", reqID)
	s.Lock()
	conn, ok := s.connMap[reqID]
	if !ok {
		conn = NewServerConn(reqID, s.CloseConn)
		s.connMap[reqID] = conn
		s.connCh <- conn
	}
	s.Unlock()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] read from body", "err", err)
		writeServiceUnavailableError(w, "read all from body:"+err.Error())
		return
	}
	p := &pushPayload{}
	if err := json.Unmarshal(b, p); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] json.Unmarshal", "err", err)
		writeServiceUnavailableError(w, "json unmarshal:"+err.Error())
		return
	}

	cipher, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] decode cipher", "err", err)
		writeServiceUnavailableError(w, "decode cipher:"+err.Error())
		return
	}

	if _, err = conn.WriteLocal(cipher); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write local", "err", err)
		writeServiceUnavailableError(w, "write local:"+err.Error())
		return
	}

	writeSuccess(w)
}

func (s *Server) CloseConn(reqID string) {
	s.Lock()
	defer s.Unlock()
	s.connMap[reqID] = nil
	delete(s.connMap, reqID)
}

func writeNotFoundError(w http.ResponseWriter) {
	http.Error(w, "404 NOT FOUND", http.StatusNotFound)
}

func writeServiceUnavailableError(w http.ResponseWriter, msg string) {
	http.Error(w, msg, http.StatusServiceUnavailable)
}

func writeSuccess(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"code":"SUCCESS", "message":"PUSH SUCCESS"}`)); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write success", "err", err)
	}
}
