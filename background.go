package easyss

import (
	"context"
	"strings"
	"time"

	"github.com/nange/easyss/v2/util"
	log "github.com/sirupsen/logrus"
)

func (ss *Easyss) background() {
	ss.mu.Lock()
	closing := ss.closing
	pingLatency := ss.pingLatency
	ss.mu.Unlock()

	tickerExec := time.NewTicker(time.Duration(ss.config.CMDIntervalTime) * time.Second)
	defer tickerExec.Stop()

	var minLatency, avgLatency, maxLatency, total time.Duration
	var count int64

	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	ticker2 := time.NewTicker(30 * time.Second)
	defer ticker2.Stop()
	for {
		select {
		case <-ticker.C:
			sendSize := ss.stat.BytesSend.Load() / (1024 * 1024)
			receiveSize := ss.stat.BytesReceive.Load() / (1024 * 1024)
			log.Infof("[EASYSS_BACKGROUND] send size: %vMB, recive size: %vMB", sendSize, receiveSize)
		case late := <-pingLatency:
			count += 1
			total += late
			if minLatency == 0 && avgLatency == 0 && maxLatency == 0 {
				minLatency, avgLatency, maxLatency = late, late, late
				continue
			}

			if minLatency > late {
				minLatency = late
			} else if maxLatency < late {
				maxLatency = late
			}
			avgLatency = total / time.Duration(count)
		case <-ticker2.C:
			if maxLatency == 0 {
				continue
			}
			log.Infof("[EASYSS_BACKGROUND] ping easyss-server latency: min:%v, avg:%v, max:%v, count:%v",
				minLatency, avgLatency, maxLatency, count)
			minLatency, avgLatency, maxLatency, count, total = 0, 0, 0, 0, 0
		case <-tickerExec.C:
			go ss.cmdInterval(ss.config.CMDInterval)
		case <-closing:
			return
		}
	}
}

func (ss *Easyss) cmdBeforeStartup() {
	cmd := ss.config.CMDBeforeStartup
	if cmd == "" {
		return
	}
	log.Infof("[CMD_BEFORE_STARTUP] exectuing %s", cmd)

	output, err := execConfigCMD(cmd, ss.Timeout()*3)
	if err != nil {
		log.Errorf("[CMD_BEFORE_STARTUP] %s: %v, output:%s", cmd, err, output)
	} else {
		log.Infof("[CMD_BEFORE_STARTUP] %s success, output:%s", cmd, output)
	}
}

func (ss *Easyss) cmdInterval(cmd string) {
	if cmd == "" {
		return
	}
	log.Infof("[CMD_INTERVAL] exectuing %s", cmd)

	output, err := execConfigCMD(cmd, ss.Timeout()*3)
	if err != nil {
		log.Errorf("[CMD_INTERVAL] %s: %v, output:%s", cmd, err, output)
	} else {
		log.Infof("[CMD_INTERVAL] %s success, output:%s", cmd, output)
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
