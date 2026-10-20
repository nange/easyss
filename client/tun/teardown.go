package tun

import (
	"errors"

	"github.com/nange/easyss/v3/log"
)

// Owner 把"谁装的谁拆"做成类型上的事实。
type Owner int

const (
	// 三类清理都由本进程做：停引擎、运行关闭脚本、恢复系统 DNS。
	OwnerLocal Owner = iota

	// 路由与系统 DNS 归提权 helper，主进程只停自己的引擎并关闭 fd。
	OwnerHelper
)

func (o Owner) String() string {
	switch o {
	case OwnerLocal:
		return "local"
	case OwnerHelper:
		return "helper"
	default:
		return "unknown"
	}
}

func ownerForConfig(cfg Config) Owner {
	if cfg.DeviceFD > 0 {
		return OwnerHelper
	}
	return OwnerLocal
}

// TeardownReason 只决定日志与错误的呈现口径，不决定做哪些步骤（那是 Owner 的事）。
type TeardownReason int

const (
	// 用户主动关闭（托盘开关、切换服务器、退出应用）。
	ReasonStop TeardownReason = iota
	// Start 建立过程中失败，不含创建脚本本身。
	ReasonStartFailed
	ReasonStartCancelled
	// 创建脚本失败：脚本先装地址后装路由，是唯一必然有东西要删的失败。
	ReasonCreateFailed
)

func (r TeardownReason) String() string {
	switch r {
	case ReasonStop:
		return "stop"
	case ReasonStartFailed:
		return "start-failed"
	case ReasonStartCancelled:
		return "start-cancelled"
	case ReasonCreateFailed:
		return "create-failed"
	default:
		return "unknown"
	}
}

// 不自己加锁：Stop 正持有 stopMu 等一个由 Start 关闭的 done，Start 路径去拿它就会死锁。
func (m *Manager) teardown(reason TeardownReason, owner Owner) error {
	m.mu.Lock()
	if m.tornDown {
		// 关脚本与恢复 DNS 只能做一次，Stop 与 Start 的 defer 可能先后到达。
		m.mu.Unlock()
		return nil
	}
	m.tornDown = true
	engineUp, deviceUp, dnsTouched := m.engineUp, m.deviceUp, m.dnsTouched
	m.engineUp, m.deviceUp = false, false
	m.mu.Unlock()

	log.Info("[TUN] teardown", "reason", reason.String(), "owner", owner.String())

	var errs []error

	// 必须先停引擎再碰设备与路由：iproute2 删不掉仍附着在 fd 上的设备，会报
	// "device or resource busy" 并留下接口与路由。
	if engineUp {
		engineStopFn(reason.String())
	}

	if owner != OwnerLocal {
		log.Info("[TUN] teardown done", "reason", reason.String(), "owner", owner.String(),
			"note", "routes and dns belong to the helper")
		return errors.Join(errs...)
	}

	if deviceUp {
		if err := closeTunDevFn(m); err != nil {
			// 清理失败不改变拆除结果，但绝不能静默：残留的分流默认路由会把全机 IPv4
			// 流量送进一个没人读的设备。
			log.Warn("[TUN] close script", "reason", reason.String(), "err", err)
			errs = append(errs, err)
		}
	}

	// 仅在本次会话改过系统 DNS 时才恢复：darwin 上恢复从未动过的 DNS 会清空 DHCP
	// 提供的服务器。
	if dnsTouched && manageSystemDNS() {
		if err := restoreDNSStepFn(m); err != nil {
			log.Warn("[TUN] restore system dns", "reason", reason.String(), "err", err)
			errs = append(errs, err)
		}
	}

	log.Info("[TUN] teardown done", "reason", reason.String(), "owner", owner.String())
	return errors.Join(errs...)
}
