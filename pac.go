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

const pacpath = "/proxy.pac"

func (ss *Easyss) SysPAC() {
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
			"Port":   strconv.Itoa(ss.config.LocalPort),
			"Global": gloabl,
		})
	})

	if err := ss.pacOn(ss.pac.url); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	defer ss.pacOff(ss.pac.url)

	go ss.pacManage()

	addr := fmt.Sprintf(":%d", ss.config.LocalPort+1)
	log.Infof("pac server started on :%v", addr)
	http.ListenAndServe(addr, nil)
}

func (ss *Easyss) pacOn(path string) error {
	if err := pac.EnsureHelperToolPresent("pac-cmd", "Set proxy auto config", ""); err != nil {
		return errors.WithStack(err)
	}
	if err := pac.On(path); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func (ss *Easyss) pacOff(path string) error {
	return errors.WithStack(pac.Off(path))
}

func (ss *Easyss) pacManage() {
	for status := range ss.pac.ch {
		switch status {
		case PACON:
			ss.pacOn(ss.pac.url)
		case PACOFF:
			ss.pacOff(ss.pac.url)
		case PACONGLOBAL:
			ss.pacOn(ss.pac.gurl)
		case PACOFFGLOBAL:
			ss.pacOff(ss.pac.gurl)
		default:
			log.Errorf("unknown pac status:%v", status)
		}
	}
}
