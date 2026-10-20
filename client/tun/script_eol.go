package tun

import (
	"bytes"
	"strings"

	"github.com/nange/easyss/v3/util"
)

// WriteScriptToTemp 把平台脚本落盘为临时文件，供提权或直接执行。它是**所有**平台脚本
// 的唯一落盘点：cmd.exe / sh 执行的是磁盘上的字节，而不是 embed 里的那一段。
func WriteScriptToTemp(name string, data []byte) (string, error) {
	return util.WriteToTemp(name, normalizeScriptEOL(name, data))
}

// .bat 必须统一成 CRLF：cmd.exe 按 OEM 代码页逐行读取批处理，中文 Windows（代码页 936）上
// LF 会让多字节注释与换行错位、注释被当命令执行；go:embed 取的是工作区字节，Raw 下载或
// 编辑器存成 LF 都不经过 .gitattributes；.sh 绝不能转 CRLF（bash 报 \r: command not found）。
func normalizeScriptEOL(name string, data []byte) []byte {
	if !strings.HasSuffix(name, ".bat") {
		return data
	}

	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
}
