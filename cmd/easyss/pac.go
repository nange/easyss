//go:build !with_notray

package main

import (
	_ "embed"
	"net/http"
	"strconv"
	"sync/atomic"
	"text/template"

	"github.com/getlantern/pac"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

//go:embed pac.txt
var pacTxt string

type PACStatus int

const (
	PACON PACStatus = iota + 1
	PACOFF
	PACONGLOBAL
	PACOFFGLOBAL
)

type PAC struct {
	path          string
	localPort     int
	localHttpPort int
	localPacPort  int
	ch            chan PACStatus
	url           string
	gurl          string
	bindAll       bool
	on            atomic.Bool

	server *http.Server
}

func NewPAC(localPort, localHttpPort, localPacPort int, path, url string, BindAll bool) *PAC {
	return &PAC{
		path:          path,
		localPort:     localPort,
		localHttpPort: localHttpPort,
		localPacPort:  localPacPort,
		ch:            make(chan PACStatus, 1),
		url:           url,
		gurl:          url + "?global=true",
		bindAll:       BindAll,
		on:            atomic.Bool{},
	}
}

func (p *PAC) LocalPAC() {
	tpl, err := template.New(p.path).Parse(pacTxt)
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc(p.path, func(w http.ResponseWriter, r *http.Request) {
		global := false

		r.ParseForm()
		globalStr := r.Form.Get("global")
		if globalStr == "true" {
			global = true
		}

		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
		tpl.Execute(w, map[string]interface{}{
			"Port":       strconv.Itoa(p.localPort),
			"Socks5Port": strconv.Itoa(p.localPort),
			"HttpPort":   strconv.Itoa(p.localHttpPort),
			"Global":     global,
		})
	})

	if err := p.pacOn(p.url); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	p.on.Store(true)

	go p.pacManage()

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

func (p *PAC) pacOn(path string) error {
	if err := pac.EnsureHelperToolPresent("pac-cmd", "Set proxy auto config", ""); err != nil {
		return errors.WithStack(err)
	}
	if err := pac.On(path); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (p *PAC) pacOff(path string) error {
	return errors.WithStack(pac.Off(path))
}

func (p *PAC) pacManage() {
	for status := range p.ch {
		switch status {
		case PACON:
			p.pacOn(p.url)
			p.on.Store(true)
		case PACOFF:
			p.pacOff(p.url)
			p.on.Store(false)
		case PACONGLOBAL:
			p.pacOn(p.gurl)
			p.on.Store(true)
		case PACOFFGLOBAL:
			p.pacOff(p.gurl)
		default:
			log.Errorf("unknown pac status:%v", status)
		}
	}
}

func (p *PAC) Close() {
	if p.on.Load() {
		p.pacOff(p.url)
	}
	close(p.ch)
	p.server.Close()
}
