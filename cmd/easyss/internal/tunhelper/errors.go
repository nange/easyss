package tunhelper

import "errors"

// ErrStartup 表示 TUN helper 在启动前退出，多为用户取消授权（意图而非故障，
// 托盘不弹通知）；跨平台哨兵，调用方用 errors.Is 判定。
var ErrStartup = errors.New("tun helper exited before startup")
