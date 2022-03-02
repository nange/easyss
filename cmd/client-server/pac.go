//go:build with_tray

//go:generate statik -src=./pac

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"text/template"

	"github.com/getlantern/pac"
	_ "github.com/nange/easyss/cmd/client-server/statik"
	"github.com/pkg/errors"
	"github.com/rakyll/statik/fs"
	log "github.com/sirupsen/logrus"
)

type PACStatus int

const (
	PACON PACStatus = iota + 1
	PACOFF
	PACONGLOBAL
	PACOFFGLOBAL
)

const PacPath = "/proxy.pac"

type PAC struct {
	path      string
	localPort int
	ch        chan PACStatus
	url       string
	gurl      string
}

func NewPAC(localPort int, path, url, grul string) *PAC {
	return &PAC{
		path:      path,
		localPort: localPort,
		ch:        make(chan PACStatus, 1),
		url:       url,
		gurl:      grul,
	}
}

func (p *PAC) SysPAC() {
	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	file, err := statikFS.Open(p.path)
	if err != nil {
		log.Fatal("open pac.txt err:", err)
	}
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("read pac.txt err:", err)
	}

	tpl, err := template.New(p.path).Parse(string(buf))
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}

	http.HandleFunc(p.path, func(w http.ResponseWriter, r *http.Request) {
		gloabl := false

		r.ParseForm()
		globalStr := r.Form.Get("global")
		if globalStr == "true" {
			gloabl = true
		}

		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
		tpl.Execute(w, map[string]interface{}{
			"Socks5Port": strconv.Itoa(p.localPort),
			"HttpPort":   strconv.Itoa(p.localPort + 1000),
			"Global":     gloabl,
		})
	})

	if err := p.pacOn(p.url); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	defer p.pacOff(p.url)

	go p.pacManage()

	addr := fmt.Sprintf(":%d", p.localPort+1)
	log.Infof("pac server started on :%v", addr)
	http.ListenAndServe(addr, nil)
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
		case PACOFF:
			p.pacOff(p.url)
		case PACONGLOBAL:
			p.pacOn(p.gurl)
		case PACOFFGLOBAL:
			p.pacOff(p.gurl)
		default:
			log.Errorf("unknown pac status:%v", status)
		}
	}
}
