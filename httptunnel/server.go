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
	"github.com/nange/easyss/v2/util/netpipe"
)

const RelayBufferSize = cipherstream.MaxCipherRelaySize

type Server struct {
	addr string

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
		Addr:    addr,
		Handler: http.DefaultServeMux,
	}

	return &Server{
		addr:        addr,
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
	http.Handle("/pull", gzhttp.GzipHandler(http.HandlerFunc(s.pull)))
	http.Handle("/push", gzhttp.GzipHandler(http.HandlerFunc(s.push)))
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
	if r.Method != http.MethodGet {
		writeNotFoundError(w)
		return
	}

	reqID := r.Header.Get(RequestIDHeader)
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
	w.Header().Set(RequestIDHeader, reqID)

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	var err error
	var n int
	var p = &pullResp{}
	for {
		n, err = conns[0].Read(buf)
		if n > 0 {
			_ = faker.FakeData(p)
			p.Ciphertext = base64.StdEncoding.EncodeToString(buf[:n])
			b, _ := json.Marshal(p)
			if _, er := w.Write(b); er != nil {
				err = errors.Join(err, er)
				log.Warn("[HTTP_TUNNEL_SERVER] response write", "err", er)
				break
			}
			p.Ciphertext = ""
		}
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		if err != nil {
			break
		}
	}
	if err != nil {
		if !errors.Is(err, io.EOF) {
			log.Warn("[HTTP_TUNNEL_SERVER] read from conn", "err", err)
		}
		s.CloseConn(reqID)
	}
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
	conns, ok := s.connMap[reqID]
	if !ok {
		conn1, conn2 := netpipe.Pipe(2 * cipherstream.MaxPayloadSize)
		conns = []net.Conn{conn1, conn2}
		s.connMap[reqID] = conns
		s.connCh <- conn2
	}
	s.notifyPull(reqID)
	s.Unlock()

	p := &pushPayload{}
	dec := json.NewDecoder(r.Body)
	var err error
	for {
		if err = dec.Decode(p); err != nil {
			if !errors.Is(err, io.EOF) {
				log.Warn("[HTTP_TUNNEL_SERVER] decode request body", "err", err, "uuid", reqID)
			}
			if p.Ciphertext == "" {
				break
			}
		}
		var cipher []byte
		cipher, err = base64.StdEncoding.DecodeString(p.Ciphertext)
		if err != nil {
			log.Warn("[HTTP_TUNNEL_SERVER] decode cipher", "err", err)
			writeServiceUnavailableError(w, "decode cipher:"+err.Error())
			break
		}
		p.Ciphertext = ""

		if _, err = conns[0].Write(cipher); err != nil {
			log.Warn("[HTTP_TUNNEL_SERVER] write local", "err", err)
			writeServiceUnavailableError(w, "write local:"+err.Error())
			break
		}
	}
	if err != nil {
		_ = conns[0].Close()
	}

	writeSuccess(w)
}

func (s *Server) CloseConn(reqID string) {
	s.Lock()
	defer s.Unlock()
	conns := s.connMap[reqID]
	if len(conns) > 0 {
		_ = conns[1].Close()
	}

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
	w.Header().Set("Content-Encoding", "gzip")
	if _, err := w.Write([]byte(`{"code":"SUCCESS", "message":"PUSH SUCCESS"}`)); err != nil {
		log.Warn("[HTTP_TUNNEL_SERVER] write success", "err", err)
	}
}
