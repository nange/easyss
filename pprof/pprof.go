package pprof

import (
	"net/http"
	"net/http/pprof"

	log "github.com/sirupsen/logrus"
)

func StartPprof() error {
	mux := http.NewServeMux()
	mux.HandleFunc("/debug/pprof/", pprof.Index)
	mux.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)
	mux.HandleFunc("/debug/pprof/profile", pprof.Profile)
	mux.HandleFunc("/debug/pprof/symbol", pprof.Symbol)
	mux.HandleFunc("/debug/pprof/trace", pprof.Trace)

	log.Infof("starting pprof server at :6060")
	if err := http.ListenAndServe(":6060", mux); err != nil {
		log.Errorf("start pprof server:%s", err.Error())
		return err
	}
	return nil
}
