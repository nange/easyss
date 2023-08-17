package pprof

import (
	"net/http"
	"net/http/pprof"

	"github.com/nange/easyss/v2/log"
)

func StartPprof() {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	log.Info("starting pprof server at :6060")
	if err := http.ListenAndServe(":6060", mux); err != nil {
		log.Error("[PPROF] start pprof server", "err", err)
	}
}
