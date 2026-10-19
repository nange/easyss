package tun

import (
	"errors"

	"github.com/nange/easyss/v3/log"
)

// Owner 声明"这次拆除由谁负责"，也就是这一次里哪些系统改动归本进程回收。
//
// 它取代了三个隐式条件：fdMode（DeviceFD>0）、SkipRouteCleanup（布尔），
// 以及由这两者中途推出来的"要不要跑关闭脚本 / 要不要恢复系统 DNS"。过去这三者
// 各自独立、又必须永远保持一致（只有 helper 路径一处同时把 DeviceFD 与
// SkipRouteCleanup 设上），漏设一个就会让非 root 的主进程去跑 pkexec 关脚本、
// 与 helper 抢同一份清理；而 session.stop 直接调 Manager.Stop 时，又会把 helper
// 装的路由与 DNS 原样留下（只因为所有调用点都恰好先走了 tunDown，这条约定既没有
// 类型也没有测试保护）。
//
// 现在"谁装的谁拆"是类型上的事实，而不是调用点的约定。
type Owner int

const (
	// OwnerLocal 表示设备、路由与系统 DNS 都由本进程安装：直连路径
	// （linux/darwin 的 root、Windows），以及 Start 跑完创建脚本之后到自己
	// 失败/被取消之前的回滚。它承担全部三类清理：停引擎、运行关闭脚本、
	// 恢复系统 DNS。
	OwnerLocal Owner = iota

	// OwnerHelper 表示设备由提权 helper 创建（fd 路径），路由与系统 DNS 也归
	// 它回收；主进程只负责停止自己的 tun2socks 引擎并关闭 fd。主进程不跑关闭
	// 脚本、不恢复 DNS：那些动作在 helper 的权限下完成，而非 root 的主进程只能
	// 再提权一次，与 helper 抢同一份清理。
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

// ownerForConfig 是 Owner 的唯一推导点：fd 路径（设备由提权 helper 创建后把
// fd 传回）归 helper 回收，其余（直连路径，含 Windows）归本进程。Start 认领
// 会话时用它定稿；平台矩阵测试也直接调它，而不是在测试里再抄一份规则。
func ownerForConfig(cfg Config) Owner {
	if cfg.DeviceFD > 0 {
		return OwnerHelper
	}
	return OwnerLocal
}

// TeardownReason 说明"为什么拆"。它不决定做哪些步骤（那是 Owner 的事），
// 只决定日志与错误的呈现方式：用户主动关闭与启动失败的可操作性完全不同。
type TeardownReason int

const (
	// ReasonStop 是用户主动关闭（托盘开关、切换服务器、退出应用）。
	ReasonStop TeardownReason = iota
	// ReasonStartFailed 是 Start 在建立过程中失败（不含创建脚本本身）。
	ReasonStartFailed
	// ReasonStartCancelled 是 Start 被 Stop 取消。
	ReasonStartCancelled
	// ReasonCreateFailed 专指创建脚本半途失败——它可能在退出码非零之前已经
	// 装上了地址与部分路由，是所有失败里唯一"必然有东西要删"的一种。
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

// teardown 撤销本次会话对系统做的改动。它是唯一执行拆除的地方：Start 的
// 失败/取消路径与 Stop 都收敛到这里，步骤集合由 owner 决定（见 Owner），
// 而每一步是否真的执行由"本次会话是否做过它"决定——拆除必须能在任意一步
// 失败之后被调用，包括还没碰过系统的情况（引擎都没起来时去跑关闭脚本只会
// 制造无关的错误）。
//
// 它不自己加锁：调用方要么已经持有 stopMu（Stop），要么位于 Start 的
// goroutine 上（失败/取消）。Start 的路径绝不能去拿 stopMu——Stop 正持有它
// 等 <-done，而 done 由 Start 的 defer 关闭，那样会直接死锁。
//
// 返回值只用于让调用方记录"清理没做成"，绝不改变拆除本身的结果。
func (m *Manager) teardown(reason TeardownReason, owner Owner) error {
	m.mu.Lock()
	if m.tornDown {
		// 同一次会话的清理只跑一遍：Stop 等在 done 上，Start 的 defer 也走
		// 拆除，两者可能先后到达；关脚本与恢复 DNS 都是"只能做一次"的动作。
		m.mu.Unlock()
		return nil
	}
	m.tornDown = true
	engineUp, deviceUp, dnsTouched := m.engineUp, m.deviceUp, m.dnsTouched
	m.engineUp, m.deviceUp = false, false
	m.mu.Unlock()

	log.Info("[TUN] teardown", "reason", reason.String(), "owner", owner.String())

	var errs []error

	// 1. 先停引擎、再碰设备与路由：引擎关闭自己持有的 fd，helper 的关闭脚本
	//    随后才能删掉接口（iproute2 无法删除仍附着在 fd 上的设备，会报
	//    "device or resource busy"，把接口连同路由一起留下）。
	if engineUp {
		engineStopFn(reason.String())
	}

	if owner != OwnerLocal {
		log.Info("[TUN] teardown done", "reason", reason.String(), "owner", owner.String(),
			"note", "routes and dns belong to the helper")
		return errors.Join(errs...)
	}

	// 2. 平台侧清理：路由与设备归本进程时才有可能需要跑关闭脚本。
	if deviceUp {
		if err := closeTunDevFn(m); err != nil {
			// 清理失败不能改变拆除的结果（调用方已经在拆了），但绝不能静默：
			// 残留的分流默认路由会把全机 IPv4 流量送进一个没人读的设备。
			log.Warn("[TUN] close script", "reason", reason.String(), "err", err)
			errs = append(errs, err)
		}
	}

	// 3. 系统 DNS。仅在本次会话真的改过它时才恢复：darwin 上把从未动过的 DNS
	//    恢复回去会清空 DHCP 提供的服务器（见 restoreDNSStep）。
	if dnsTouched && manageSystemDNS() {
		if err := restoreDNSStepFn(m); err != nil {
			log.Warn("[TUN] restore system dns", "reason", reason.String(), "err", err)
			errs = append(errs, err)
		}
	}

	log.Info("[TUN] teardown done", "reason", reason.String(), "owner", owner.String())
	return errors.Join(errs...)
}
