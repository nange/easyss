package easyss

import (
	"io"
	"time"

	"github.com/nange/easyss/cipherstream"
	"github.com/nange/easyss/util"
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

var headerBytes = util.NewBytes(util.Http2HeaderLen)

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

func NewConnState(s state, buf []byte) *ConnState {
	cs := &ConnState{
		state: s,
		buf:   buf,
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
	log.Debug("start FINWait1 state")
	defer log.Debug("end FINWait1 state")

	cs.state = FIN_WAIT1

	header := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(header)

	fin := util.EncodeFINRstStreamHeader(header)
	_, err := conn.Write(fin)
	if err != nil {
		log.Debugf("conn.Write FIN err:%v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	for {
		_, err = conn.Read(cs.buf)
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

	log.Debugf("except get ErrFINRSTStream or ErrACKRSTStream, but get: %v", err)
	cs.err = err
	cs.fn = nil
	return cs
}

func (cs *ConnState) FINWait2(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start FINWait2 state")
	defer log.Debug("end FINWait2 state")
	cs.state = FIN_WAIT2
	var err error
	for {
		_, err = conn.Read(cs.buf)
		if err != nil {
			break
		}
	}
	if !cipherstream.FINRSTStreamErr(err) {
		log.Debugf("except get ErrFINRSTStream, but get: %+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	header := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(header)

	ack := util.EncodeACKRstStreamHeader(header)
	_, err = conn.Write(ack)
	if err != nil {
		log.Debugf("conn.Write ACK err:%+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.TimeWait
	return cs
}

func (cs *ConnState) LastACK(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start LastACK state")
	defer log.Debug("end LastACK state")

	cs.state = LAST_ACK

	header := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(header)

	fin := util.EncodeFINRstStreamHeader(header)
	_, err := conn.Write(fin)
	if err != nil {
		log.Debugf("conn.Write FIN err:%+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.Closed
	return cs
}

func (cs *ConnState) Closing(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start Closing state")
	defer log.Debug("end Closing state")

	cs.state = CLOSING

	header := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(header)

	ack := util.EncodeACKRstStreamHeader(header)
	_, err := conn.Write(ack)
	if err != nil {
		log.Debugf("conn.Write ACK err:%+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.Closed
	return cs
}

func (cs *ConnState) CloseWait(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start CloseWait state")
	defer log.Debug("end CloseWait state")

	cs.state = CLOSE_WAIT

	header := headerBytes.Get(util.Http2HeaderLen)
	defer headerBytes.Put(header)

	ack := util.EncodeACKRstStreamHeader(header)
	_, err := conn.Write(ack)
	if err != nil {
		log.Debugf("conn.Write ack err:%+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	cs.fn = cs.LastACK
	return cs
}

func (cs *ConnState) TimeWait(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start TimeWait state")
	defer log.Debug("end TimeWait state")

	cs.state = TIME_WAIT
	log.Debug("in TimeWait state, we should end state machine immediately")

	// if conn is tcp connection, set the deadline to default
	var err error
	if cs, ok := conn.(*cipherstream.CipherStream); ok {
		err = cs.Conn.SetDeadline(time.Time{})
		log.Debug("set tcp connection deadline to default")
	}
	if err != nil {
		log.Warnf("conn.SetDeadline to default err:%v", err)
		cs.err = err
	}
	cs.fn = nil
	return cs
}

func (cs *ConnState) Closed(conn io.ReadWriteCloser) *ConnState {
	log.Debug("start Closed state")
	defer log.Debug("end Closed state")

	cs.state = CLOSED
	var err error
	for {
		_, err = conn.Read(cs.buf)
		if err != nil {
			break
		}
	}
	if !cipherstream.ACKRSTStreamErr(err) {
		log.Debugf("except get ErrACKRSTStream, but get: %+v", err)
		cs.err = err
		cs.fn = nil
		return cs
	}

	// if conn is tcp connection, set the deadline to default
	if cs, ok := conn.(*cipherstream.CipherStream); ok {
		err = cs.Conn.SetDeadline(time.Time{})
		log.Debug("set tcp connection deadline to default")
	}
	if err != nil {
		log.Warnf("conn.SetDeadline to default err:%+v", err)
		cs.err = err
	}
	cs.fn = nil

	return cs
}
