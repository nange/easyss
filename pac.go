//go:generate statik -src=./pac

package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"text/template"

	"github.com/getlantern/pac"
	_ "github.com/nange/easyss/statik"
	"github.com/pkg/errors"
	"github.com/rakyll/statik/fs"
	log "github.com/sirupsen/logrus"
)

const pacpath = "/pac.txt"

type PAC struct {
	localport int
	pacChan   <-chan PACStatus
	pacURL    string
	pacGURL   string
}

func NewPAC(localport int, pacChan <-chan PACStatus) *PAC {
	p := &PAC{
		localport: localport,
		pacChan:   pacChan,
		pacURL:    fmt.Sprintf("http://localhost:%d%s", localport+1, pacpath),
		pacGURL:   fmt.Sprintf("http://localhost:%d%s?global=true", localport+1, pacpath),
	}
	return p
}

func (p *PAC) Serve() {
	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}
	file, err := statikFS.Open(pacpath)
	if err != nil {
		log.Fatal("open pac.txt err:", err)
	}
	buf, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatal("read pac.txt err:", err)
	}

	tpl, err := template.New(pacpath).Parse(string(buf))
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}

	http.HandleFunc(pacpath, func(w http.ResponseWriter, r *http.Request) {
		gloabl := false

		r.ParseForm()
		globalStr := r.Form.Get("global")
		if globalStr == "true" {
			gloabl = true
		}

		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
		tpl.Execute(w, map[string]interface{}{
			"Port":   strconv.Itoa(p.localport),
			"Global": gloabl,
		})
	})

	if err := p.pacOn(p.pacURL); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	defer p.pacOff(p.pacURL)

	go p.pacManage(p.pacChan)

	addr := fmt.Sprintf(":%d", p.localport+1)
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

func (p *PAC) pacManage(pacChan <-chan PACStatus) {
	for status := range pacChan {
		switch status {
		case PACON:
			p.pacOn(p.pacURL)
		case PACOFF:
			p.pacOff(p.pacURL)
		case PACONGLOBAL:
			p.pacOn(p.pacGURL)
		case PACOFFGLOBAL:
			p.pacOn(p.pacURL)
		}

	}
}
