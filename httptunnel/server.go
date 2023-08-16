package httptunnel

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-faker/faker/v4"
	"github.com/klauspost/compress/gzhttp"
	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
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
		log.Fatalf("[HTTP_TUNNEL_SERVER] net.Listen:%v", err)
	}
	if s.tlsConfig != nil {
		ln = tls.NewListener(ln, s.tlsConfig)
	}

	log.Infof("[HTTP_TUNNEL_SERVER] listen http tunnel at:%v", s.addr)
	log.Warnf("[HTTP_TUNNEL_SERVER] http serve:%v", s.server.Serve(ln))
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
		log.Warnf("[HTTP_TUNNEL_SERVER] pull uuid:%v not found", reqID)
		writeNotFoundError(w)
		return
	}
	log.Debugf("[HTTP_TUNNEL_SERVER] pull uuid:%v", reqID)

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Transfer-Encoding", "chunked")

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	for {
		n, err := conn.ReadLocal(buf)
		if n > 0 {
			p := &pullResp{}
			if err := faker.FakeData(p); err != nil {
				log.Warnf("[HTTP_TUNNEL_SERVER] fake data:%v", err)
				writeServiceUnavailableError(w, "fake data:"+err.Error())
				return
			}
			p.Ciphertext = base64.StdEncoding.EncodeToString(buf[:n])

			b, _ := json.Marshal(p)
			if _, err = w.Write(b); err != nil {
				log.Warnf("[HTTP_TUNNEL_SERVER] response write:%v", err)
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warnf("[HTTP_TUNNEL_SERVER] read from conn:%v", err)
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
		log.Warnf("[HTTP_TUNNEL_SERVER] push uuid is empty")
		writeNotFoundError(w)
		return
	}
	log.Debugf("[HTTP_TUNNEL_SERVER] push uuid:%v", reqID)
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
		log.Warnf("[HTTP_TUNNEL_SERVER] read from body:%v", err)
		writeServiceUnavailableError(w, "read all from body:"+err.Error())
		return
	}
	p := &pushPayload{}
	if err := json.Unmarshal(b, p); err != nil {
		log.Warnf("[HTTP_TUNNEL_SERVER] json.Unmarshal:%v", err)
		writeServiceUnavailableError(w, "json unmarshal:"+err.Error())
		return
	}

	cipher, err := base64.StdEncoding.DecodeString(p.Ciphertext)
	if err != nil {
		log.Warnf("[HTTP_TUNNEL_SERVER] decode cipher:%v", err)
		writeServiceUnavailableError(w, "decode cipher:"+err.Error())
		return
	}

	if _, err = conn.WriteLocal(cipher); err != nil {
		log.Warnf("[HTTP_TUNNEL_SERVER] write local:%v", err)
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
		log.Warnf("[HTTP_TUNNEL_SERVER] write success:%v", err)
	}
}
