//go:build headless

package logview

// headless 构建没有托盘与日志菜单，日志查看器不会被使用。
func Default() Opener { return Opener{} }
