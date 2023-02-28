package http_tunnel

import (
	"errors"
	"io"
	"net"
	"net/http"
	"sync"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/util/bytespool"
	log "github.com/sirupsen/logrus"
)

const RelayBufferSize = cipherstream.MaxCipherRelaySize

type Server struct {
	addr string

	sync.Mutex
	connMap map[string]*Conn
	connCh  chan *Conn
	closing chan struct{}
}

func NewServer(addr string) *Server {
	return &Server{
		addr:    addr,
		connMap: make(map[string]*Conn, 128),
		connCh:  make(chan *Conn, 1),
		closing: make(chan struct{}, 1),
	}
}

func (s *Server) Listen() {
	s.handler()
	// TODO: 改为server模式，支持手动close
	log.Infof("[HTTP_TUNNEL_SERVER] listen at:%v", s.addr)
	log.Warnf("[HTTP_TUNNEL_SERVER] listen and serve:%v", http.ListenAndServe(s.addr, nil))
}

func (s *Server) Close() {
	s.Lock()
	defer s.Unlock()
	close(s.closing)
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
	http.HandleFunc("/pull", s.pull)
	http.HandleFunc("/push", s.push)
}

func (s *Server) pull(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-ID")
	s.Lock()
	conn, ok := s.connMap[reqID]
	s.Unlock()
	if !ok {
		log.Warnf("[HTTP_TUNNEL_SERVER] pull uuid:%v not found", reqID)
		writeNotFoundError(w)
		return
	}
	log.Infof("[HTTP_TUNNEL_SERVER] pull uuid:%v", reqID)

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Transfer-Encoding", "chunked")

	buf := bytespool.Get(RelayBufferSize)
	defer bytespool.MustPut(buf)

	defer conn.Close()
	for {
		n, err := conn.ReadLocal(buf)
		if n > 0 {
			if _, err = w.Write(buf[:n]); err != nil {
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
	reqID := r.Header.Get("X-Request-ID")
	if reqID == "" {
		log.Warnf("[HTTP_TUNNEL_SERVER] push uuid is empty")
		writeNotFoundError(w)
		return
	}
	log.Infof("[HTTP_TUNNEL_SERVER] push uuid:%v", reqID)
	s.Lock()
	conn, ok := s.connMap[reqID]
	if !ok {
		conn = NewConn()
		s.connMap[reqID] = conn
		s.connCh <- conn
	}
	s.Unlock()

	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Warnf("[HTTP_TUNNEL_SERVER] read from body:%v", err)
		writeServiceUnavailableError(w)
		return
	}
	if _, err = conn.WriteLocal(b); err != nil {
		log.Warnf("[HTTP_TUNNEL_SERVER] write local:%v", err)
		writeServiceUnavailableError(w)
		return
	}

	writeNoContent(w, reqID)
}

func writeNotFoundError(w http.ResponseWriter) {
	http.Error(w, "404 NOT FOUND", http.StatusNotFound)
}

func writeServiceUnavailableError(w http.ResponseWriter) {
	http.Error(w, "Service Unavailable", http.StatusServiceUnavailable)
}

func writeNoContent(w http.ResponseWriter, msg string) {
	w.WriteHeader(http.StatusNoContent)
}
