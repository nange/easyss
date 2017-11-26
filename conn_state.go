package main

import (
	"io"
	"net"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/utils"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

type state int

const (
	ESTABLISHED state = iota
	FIN_WAIT1
	FIN_WAIT2
	LAST_ACK
	CLOSING
	CLOSE_WAIT
	TIME_WAIT
	CLOSED
)

var stateMap = map[state]string{
	ESTABLISHED: "state: ESTABLISHED",
	FIN_WAIT1:   "state: FIN_WAIT1",
	FIN_WAIT2:   "state: FIN_WAIT2",
	LAST_ACK:    "state: LAST_ACK",
	CLOSING:     "state: CLOSING",
	CLOSE_WAIT:  "state: CLOSE_WAIT",
	TIME_WAIT:   "state: TIME_WAIT",
	CLOSED:      "state: CLOSED",
}

func (s state) String() string {
	if _, ok := stateMap[s]; ok {
		return stateMap[s]
	}
	return "unknown state"
}

type ConnStateFn func(conn io.ReadWriteCloser) *ConnState

type ConnState struct {
	fn    ConnStateFn
	state state
	err   error
	buf   []byte
}

func NewConnState(s state) *ConnState {
	cs := &ConnState{
		state: s,
		buf:   make([]byte, 64),
	}
	statefnMap := map[state]ConnStateFn{
		FIN_WAIT1:  cs.FINWait1,
		FIN_WAIT2:  cs.FINWait2,
		LAST_ACK:   cs.LastACK,
		CLOSING:    cs.Closing,
		CLOSE_WAIT: cs.CloseWait,
		TIME_WAIT:  cs.TimeWait,
		CLOSED:     cs.Closed,
	}
	if statefn, ok := statefnMap[s]; ok {
		cs.fn = statefn
	}
	return cs
}

func (cs *ConnState) FINWait1(conn io.ReadWriteCloser) *ConnState {
	log.Info("start FINWait1 state")
	defer log.Info("end FINWait1 state")

	cs.state = FIN_WAIT1
	fin := utils.NewFINRstStreamHeader()
	_, err := conn.Write(fin)
	if err != nil {
		log.Errorf("conn.Write FIN err:%+v", errors.WithStack(err))
		cs.err = err
		cs.fn = nil
		return cs
	}

	for {
		_, err = conn.Read(cs.buf)
		log.Infof("FINWAIT1 conn.Read, err:%v", err)
		if err != nil {
			break
		}
	}
	if cipherstream.FINRSTStreamErr(err) {
		cs.fn = cs.Closing
		return cs
	}

	if cipherstream.ACKRSTStreamErr(err) {
		cs.fn = cs.FINWait2
		return cs
	}

	log.Errorf("except get ErrFINRSTStream or ErrACKRSTStream, but get: %v", err)
	cs.err = err
	cs.fn = nil
	return cs
}

func (cs *ConnState) FINWait2(conn io.ReadWriteCloser) *ConnState {
	log.Info("start FINWait2 state")
	defer log.Info("end FINWait2 state")
	cs.state = FIN_WAIT2
	var err error
	for {
		_, err = conn.Read(cs.buf)
		if err != nil {
			break
		}
	}
	if !cipherstream.FINRSTStreamErr(err) {
		log.Errorf("except get ErrFINRSTStream, but get: %+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	ack := utils.NewACKRstStreamHeader()
	_, err = conn.Write(ack)
	if err != nil {
		log.Errorf("conn.Write ACK err:%+v", errors.WithStack(err))
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.TimeWait
	return cs
}

func (cs *ConnState) LastACK(conn io.ReadWriteCloser) *ConnState {
	log.Info("start LastACK state")
	defer log.Info("end LastACK state")

	cs.state = LAST_ACK
	fin := utils.NewFINRstStreamHeader()
	_, err := conn.Write(fin)
	if err != nil {
		log.Errorf("conn.Write FIN err:%+v", errors.WithStack(err))
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.Closed
	return cs
}

func (cs *ConnState) Closing(conn io.ReadWriteCloser) *ConnState {
	log.Info("start Closing state")
	defer log.Info("end Closing state")

	cs.state = CLOSING
	ack := utils.NewACKRstStreamHeader()
	_, err = conn.Write(ack)
	if err != nil {
		log.Errorf("conn.Write ACK err:%+v", errors.WithStack(err))
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.Closed
	return cs
}

func (cs *ConnState) CloseWait(conn io.ReadWriteCloser) *ConnState {
	log.Info("start CloseWait state")
	defer log.Info("end CloseWait state")

	cs.state = CLOSE_WAIT
	ack := utils.NewACKRstStreamHeader()
	_, err := conn.Write(ack)
	if err != nil {
		log.Errorf("conn.Write ack err:%+v", errors.WithStack(err))
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.LastACK
	return cs
}

func (cs *ConnState) TimeWait(conn io.ReadWriteCloser) *ConnState {
	log.Info("start TimeWait state")
	defer log.Info("end TimeWait state")

	cs.state = TIME_WAIT
	log.Info("in our TimeWait state, we should end our state machine immediately")

	// if conn is tcp connection, set the deadline to default
	var err error
	if cs, ok := conn.(*cipherstream.CipherStream); ok {
		if c, ok := cs.ReadWriteCloser.(net.Conn); ok {
			err = c.SetDeadline(time.Time{})
			log.Info("set tcp connection deadline to default")
		}
	}
	if err != nil {
		log.Errorf("conn.SetDeadline to default err:%+v", errors.WithStack(err))
		cs.err = err
	}
	cs.fn = nil
	return cs
}

func (cs *ConnState) Closed(conn io.ReadWriteCloser) *ConnState {
	log.Info("start Closed state")
	defer log.Info("end Closed state")

	cs.state = CLOSED
	var err error
	for {
		_, err = conn.Read(cs.buf)
		if err != nil {
			break
		}
	}
	if !cipherstream.ACKRSTStreamErr(err) {
		log.Errorf("except get ErrACKRSTStream, but get: %+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	// if conn is tcp connection, set the deadline to default
	if cs, ok := conn.(*cipherstream.CipherStream); ok {
		if c, ok := cs.ReadWriteCloser.(net.Conn); ok {
			err = c.SetDeadline(time.Time{})
			log.Info("set tcp connection deadline to default")
		}
	}
	if err != nil {
		log.Errorf("conn.SetDeadline to default err:%+v", errors.WithStack(err))
		cs.err = err
	}
	cs.fn = nil

	return cs
}
