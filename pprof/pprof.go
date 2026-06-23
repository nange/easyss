package pprof

import (
	"context"
	"net/http"
	"net/http/pprof"
	"time"

	"github.com/nange/easyss/v3/log"
)

const defaultAddr = "127.0.0.1:6060"

func StartPprof() *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	srv := &http.Server{Addr: defaultAddr, Handler: mux}

	log.Info("starting pprof server", "addr", defaultAddr)
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("[PPROF] start pprof server", "err", err)
		}
	}()
	return srv
}

func StopPprof(srv *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("[PPROF] shutdown pprof server", "err", err)
	}
}
