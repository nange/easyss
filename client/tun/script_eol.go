package tun

import (
	"bytes"
	"strings"

	"github.com/nange/easyss/v3/util"
)

// WriteScriptToTemp 把平台脚本落盘为临时文件，供提权或直接执行。它是**所有**平台脚本的
// 唯一落盘点：本包的 TUN 创建/关闭脚本，以及 cmd/easyss 提权 helper 的脚本，都必须走这里
// ——cmd.exe / sh 执行的是磁盘上的字节，而不是 embed 里的那一段。
func WriteScriptToTemp(name string, data []byte) (string, error) {
	return util.WriteToTemp(name, normalizeScriptEOL(name, data))
}

// normalizeScriptEOL 返回落盘执行的脚本字节：批处理脚本的行尾统一成 CRLF，其余原样返回。
//
// cmd.exe 按 OEM 代码页逐行读取批处理文件，在中文 Windows（OEM 代码页 936）上，LF 行尾会
// 让多字节注释的字节与换行错位：注释文字被当成命令执行、真正的命令行被截断。实测
// create_tun_dev_windows.bat 在 LF 下一条配置命令都发不出去（16 条 → 0 条）并以 1 退出。
//
// 仓库里 *.bat 的行尾由 .gitattributes 的 "*.bat text eol=crlf" 保证，但 go:embed 取的是
// 工作区字节，而工作区可能来自 Raw 单文件下载、被编辑器存成 LF、或第三方镜像——这些来源
// 不经过属性转换。行尾因此在这里兜住，脚本内容不必为来源负责（scripts_test.go 的断言退回
// 它本来的角色：挡住仓库被误存成 LF）。
//
// 只处理 .bat：shell 脚本带 CRLF 会让 bash 报 "\r: command not found"，.sh 必须原样。
// 先归一化成 LF 再补 CR，因此对已经是 CRLF 的输入是幂等的，不会写出 \r\r\n。
func normalizeScriptEOL(name string, data []byte) []byte {
	if !strings.HasSuffix(name, ".bat") {
		return data
	}

	lf := bytes.ReplaceAll(data, []byte("\r\n"), []byte("\n"))
	return bytes.ReplaceAll(lf, []byte("\n"), []byte("\r\n"))
}
