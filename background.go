package easyss

import (
	"context"
	"errors"
	"math/rand"
	"strconv"
	"strings"
	"time"

	"github.com/nange/easyss/v2/cipherstream"
	"github.com/nange/easyss/v2/log"
	"github.com/nange/easyss/v2/util"
)

func (ss *Easyss) background() {
	ss.mu.Lock()
	closing := ss.closing
	ss.mu.Unlock()

	tickerExec := time.NewTicker(time.Duration(ss.config.CMDIntervalTime) * time.Second)
	defer tickerExec.Stop()

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()

	n := rand.Int63n(30)
	if n < 15 {
		n = 15
	}
	ticker2 := time.NewTicker(time.Duration(n) * time.Second)
	defer ticker2.Stop()

	go ss.pingOnce()

	for {
		select {
		case <-ticker.C:
			sendSize := ss.stat.BytesSend.Load() / (1024 * 1024)
			receiveSize := ss.stat.BytesReceive.Load() / (1024 * 1024)
			log.Info("[EASYSS_BACKGROUND]", "send_size(MB)", sendSize, "receive_size(MB)", receiveSize)
		case <-ticker2.C:
			go ss.pingOnce()
		case <-tickerExec.C:
			go ss.cmdInterval(ss.config.CMDInterval)
		case <-closing:
			return
		}
	}
}

func (ss *Easyss) pingOnce() {
	var since time.Duration
	var err error
	for i := 1; i <= 3; i++ {
		since, err = ss.pingLatency()
		if err != nil {
			time.Sleep(time.Duration(i) * time.Second)
			continue
		}
		break
	}
	if err != nil {
		log.Error("[EASYSS_BACKGROUND] ping", "err", err)
		select {
		case ss.pingLatCh <- "error":
		default:
		}
		return
	}

	since = (since / time.Millisecond) * time.Millisecond
	select {
	case ss.pingLatCh <- since.String():
	default:
	}
	log.Info("[EASYSS_BACKGROUND] ping", "latency", since.String())
}

func (ss *Easyss) pingLatency() (time.Duration, error) {
	conn, err := ss.AvailableConn(true)
	if err != nil {
		log.Error("[EASYSS_BACKGROUND] got available conn for ping test", "err", err)
		return 0, err
	}

	conn, _ = cipherstream.New(conn, ss.Password(), cipherstream.MethodAes256GCM, cipherstream.FrameTypePing)
	csStream := conn.(*cipherstream.CipherStream)
	defer func() {
		_ = csStream.SetReadDeadline(time.Time{})
		if err != nil {
			csStream.MarkConnUnusable()
		}
		_ = csStream.Close()
	}()

	if err := csStream.SetReadDeadline(time.Now().Add(ss.PingTimeout())); err != nil {
		log.Error("[EASYSS_BACKGROUND] set read deadline for cipher stream", "err", err)
		return 0, err
	}

	var frame *cipherstream.Frame
	frame, err = csStream.ReadFrame()
	if err != nil {
		log.Error("[EASYSS_BACKGROUND] read frame from cipher stream", "err", err)
		return 0, err
	}
	if !frame.IsPingFrame() {
		log.Error("[EASYSS_BACKGROUND] except got ping frame, bug got", "frame", frame.FrameType().String())
		return 0, errors.New("isn't ping frame")
	}

	startStr := frame.RawDataPayload()
	var ts int64
	ts, err = strconv.ParseInt(string(startStr), 10, 64)
	if err != nil {
		log.Error("[EASYSS_BACKGROUND] parse start timestamp for ping test", "err", err)
		return 0, err
	}
	since := time.Since(time.Unix(0, ts))

	return since, nil
}

func (ss *Easyss) cmdBeforeStartup() error {
	cmd := ss.config.CMDBeforeStartup
	if cmd == "" {
		return nil
	}
	log.Info("[CMD_BEFORE_STARTUP] executing", "cmd", cmd)

	output, err := execConfigCMD(cmd, ss.CMDTimeout())
	if err != nil {
		log.Error("[CMD_BEFORE_STARTUP] failure", "cmd", cmd, "err", err, "output", output)
	} else {
		log.Info("[CMD_BEFORE_STARTUP] success", "cmd", cmd, "output", output)
	}
	return err
}

func (ss *Easyss) cmdInterval(cmd string) {
	if cmd == "" {
		return
	}
	log.Info("[CMD_INTERVAL] executing", "cmd", cmd)

	output, err := execConfigCMD(cmd, ss.CMDTimeout())
	if err != nil {
		log.Error("[CMD_INTERVAL] failure", "cmd", cmd, "err", err, "output", output)
	} else {
		log.Info("[CMD_INTERVAL] success", "cmd", cmd, "output", output)
	}
}

func execConfigCMD(cmd string, timeout time.Duration) (string, error) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return "", nil
	}

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(timeout))
	defer cancel()

	var output string
	var err error
	items := strings.Split(cmd, " ")
	if len(items) == 1 {
		output, err = util.CommandContext(ctx, items[0])
	} else {
		var args []string
		for i := 1; i < len(items); i++ {
			if items[i] != "" {
				args = append(args, items[i])
			}
		}
		output, err = util.CommandContext(ctx, items[0], args...)
	}

	return output, err
}
