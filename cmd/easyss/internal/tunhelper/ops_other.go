//go:build !darwin && !linux

package tunhelper

// 其他平台没有提权 helper 与路由残留探测。
type ops struct{}
