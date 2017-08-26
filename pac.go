//go:generate statik -src=./pac

package main

import (
	"fmt"
	"net/http"

	"github.com/getlantern/pac"
	_ "github.com/nange/easyss/statik"
	"github.com/pkg/errors"
	"github.com/rakyll/statik/fs"
	log "github.com/sirupsen/logrus"
)

func servePAC(config *Config) {
	statikFS, err := fs.New()
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/pac/", http.StripPrefix("/pac/", http.FileServer(statikFS)))
	addr := fmt.Sprintf(":%d", config.LocalPort+1)

	pacpath := fmt.Sprintf("http://localhost:%d/pac/pac.txt", config.LocalPort+1)
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
