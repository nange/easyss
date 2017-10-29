package main

import (
	"crypto/tls"
	"fmt"
	"time"

	quic "github.com/lucas-clemente/quic-go"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type sessAction int

const (
	GET_STREAM sessAction = iota + 1
)

type sessOpts struct {
	action sessAction
	ret    chan quic.Stream
}

func NewSession(addr string) (quic.Session, error) {
	return quic.DialAddr(addr,
		&tls.Config{InsecureSkipVerify: true},
		&quic.Config{IdleTimeout: time.Minute})
}

func (ss *Easyss) sessManage() {
	for {
		select {
		case opts := <-ss.sessChan:
			if opts.action == GET_STREAM {
			Again:
				if ss.localSess == nil {
					addr := fmt.Sprintf("%s:%d", ss.config.Server, ss.config.ServerPort)
					sess, err := NewSession(addr)
					if err != nil {
						log.Errorf("new session err:%v, server:%v, port:%v",
							errors.WithStack(err), ss.config.Server, ss.config.ServerPort)
						opts.ret <- nil
						break
					}
					ss.localSess = sess
				}

				stream, err := ss.localSess.OpenStreamSync()
				if err != nil {
					log.Warnf("local session open stream failed, maybe session have been closed, create a new seesion, message:%v",
						errors.WithStack(err))
					ss.localSess = nil
					goto Again
				}

				opts.ret <- stream
			}

		}
	}
}

func (ss *Easyss) getStream() quic.Stream {
	ret := make(chan quic.Stream, 1)
	ss.sessChan <- sessOpts{action: GET_STREAM, ret: ret}

	return <-ret
}
