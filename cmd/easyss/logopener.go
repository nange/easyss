package main

// logOpener 是打开日志文件所需的平台依赖：查找可执行文件与用默认程序打开。
// 类型在 headless 构建下也要存在：App 的依赖结构体由启动路径共用。
type logOpener struct {
	lookPath func(string) (string, error)
	open     func(string) error
}
