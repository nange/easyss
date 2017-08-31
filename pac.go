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

func ServePAC(config *Config) {
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
		log.Fatal(err)
	}

	tpl, err := template.New(pacpath).Parse(string(buf))
	if err != nil {
		log.Fatalf("template parse pac err:%v", err)
	}
	http.HandleFunc(pacpath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript; charset=UTF-8")
		tpl.Execute(w, map[string]string{"Port": strconv.Itoa(config.LocalPort)})
	})
	addr := fmt.Sprintf(":%d", config.LocalPort+1)

	pacpath := fmt.Sprintf("http://localhost:%d/pac.txt", config.LocalPort+1)
	if err := pacOn(pacpath); err != nil {
		log.Fatalf("set system pac err:%v", err)
	}
	defer pacOff(pacpath)

	log.Infof("pac server started on :%v", addr)
	http.ListenAndServe(addr, nil)
}

func pacOn(path string) error {
	if err := pac.EnsureHelperToolPresent("pac-cmd", "Set proxy auto config", ""); err != nil {
		return errors.WithStack(err)
	}
	if err := pac.On(path); err != nil {
		return errors.WithStack(err)
	}

	return nil
}

func pacOff(path string) error {
	return errors.WithStack(pac.Off(path))
}
