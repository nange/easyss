package singleton

import "errors"

// ErrAnotherInstance 表示单实例锁被另一个实例持有，区别于锁创建失败：
// 启动路径视为无操作以 0 退出，更新恢复路径只警告并继续无锁运行。
var ErrAnotherInstance = errors.New("another easyss instance is already running")
