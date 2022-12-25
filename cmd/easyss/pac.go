//go:build !with_notray

package main

import (
	_ "embed"
	"fmt"
	"net/http"
	"strconv"
	"sync/atomic"
	"text/template"

	"github.com/getlantern/pac"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const PacPath = "/proxy.pac"

//go:embed pac.txt
var pacTxt string

type PAC struct {
	path         string
	localPort    int
	localPacPort int
	url          string
	bindAll      bool
	on           atomic.Bool

	server *http.Server
}

func NewPAC(localPort, localPacPort int, BindAll bool) *PAC {
	url := fmt.Sprintf("http://localhost:%d%s", localPacPort, PacPath)
	return &PAC{
		localPort:    localPort,
		localPacPort: localPacPort,
		url:          url,
		bindAll:      BindAll,
		on:           atomic.Bool{},
	}
}

func (p *PAC) LocalPAC() {
	tpl, err := template.New("pac").Parse(pacTxt)
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc(PacPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")

		tpl.Execute(w, map[string]interface{}{
			"Port": strconv.Itoa(p.localPort),
		})
	})

	if err := p.PACOn(); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	p.on.Store(true)

	var addr string
	if p.bindAll {
		addr = ":" + strconv.Itoa(p.localPacPort)
	} else {
		addr = "127.0.0.1:" + strconv.Itoa(p.localPacPort)
	}
	log.Infof("starting local pac server at %v", addr)

	server := &http.Server{Addr: addr, Handler: handler}
	p.server = server

	log.Warnf("pac http server err:%s", server.ListenAndServe())
}

func (p *PAC) PACOn() error {
	if err := pac.EnsureHelperToolPresent("pac-cmd", "Set proxy auto config", ""); err != nil {
		return errors.WithStack(err)
	}
	if err := pac.On(p.url); err != nil {
		return err
	}
	p.on.Store(true)

	return nil
}

func (p *PAC) PACOff() error {
	if err := pac.Off(p.url); err != nil {
		return err
	}
	p.on.Store(false)

	return nil
}

func (p *PAC) Close() {
	if p.on.Load() {
		p.PACOff()
	}
	p.server.Close()
}
