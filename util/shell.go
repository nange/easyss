package util

import "strings"

// shellQuote 为 shell 引用单个参数。不含任何 shell 特殊字符的参数
// 保持原样（空字符串除外，会被引号包裹）。
func shellQuote(s string) string {
	const specials = " \t\n\"'\\$`&|;<>()*?[]{}~#!"

	if s != "" && !strings.ContainsAny(s, specials) {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// ShellJoin 引用每个参数并用空格连接，因此结果可以交给 shell
// 或期望单条 shell 命令字符串的终端模拟器。
func ShellJoin(args []string) string {
	quoted := make([]string, 0, len(args))
	for _, arg := range args {
		quoted = append(quoted, shellQuote(arg))
	}

	return strings.Join(quoted, " ")
}
