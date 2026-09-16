package main

import "errors"

// errAnotherInstance 报告单实例锁被另一个运行中的实例持有，
// 区别于锁本身创建失败。启动路径遇到它以 0 退出（二次启动是无操作），
// 而托盘的更新后恢复路径只警告：应用在无锁的情况下继续运行，
// 而不是消失。
var errAnotherInstance = errors.New("another easyss instance is already running")
