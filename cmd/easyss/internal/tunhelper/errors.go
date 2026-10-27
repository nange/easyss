package tunhelper

import (
	"errors"
	"fmt"
	"io/fs"
)

// ErrStartup 表示 TUN helper 在启动前退出，多为用户取消授权（意图而非故障，
// 托盘不弹通知）；跨平台哨兵，调用方用 errors.Is 判定。
var ErrStartup = errors.New("tun helper exited before startup")

// ErrElevationRequired 表示 helper 进程没有拿到管理员令牌：wintun 适配器只能由管理员
// 创建，未提权就启动引擎只会得到 wintun 的 "Access is denied"。同时满足
// errors.Is(err, fs.ErrPermission)，托盘据此提示需要管理员权限，而不是当成可重试的失败。
var ErrElevationRequired = fmt.Errorf("%w: tun helper is not elevated", fs.ErrPermission)
