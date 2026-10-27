//go:build windows

package tunhelper

// ops 是 Windows 的 TUN 会话复核：主进程非提权，只能读路由表判断 helper 是否清干净，
// 不能像 unix 那样在复核失败时自己再执行一次关闭脚本。
type ops struct {
	probe func(tunGW string) (string, bool)
}
