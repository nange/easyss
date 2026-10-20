package version

// 参考：https://github.com/qiniu/version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	unknownProperty = ""
)

// Compiler 是 runtime.Compiler 的便捷别名。
const Compiler = runtime.Compiler

// 这些变量由 Makefile 的 -ldflags 注入，其余在 init 里从构建信息与 runtime 补齐。
var (
	// GoVersion 是构建该二进制所用的 Go 工具链版本，未注入时取 runtime.Version()。
	GoVersion = unknownProperty
	// GitCommit 是构建时 Git 仓库 HEAD 的提交哈希，未注入时由 runtime/debug 收集。
	GitCommit = unknownProperty
	// GitCommitDate 是 GitCommit 的提交日期，RFC3339 格式。
	GitCommitDate = unknownProperty
	// GitTreeState 在构建时源码树有本地修改时为 "dirty"，否则为空。
	GitTreeState = unknownProperty
	// GitTag 是构建时注入的标签名，为空时 Print 不显示它。
	GitTag = unknownProperty
	// BuildDate 是构建时注入的构建时间字符串，为空时 Print 不显示它。
	BuildDate = unknownProperty
	// Platform 是 "GOOS/GOARCH" 形式的字符串，例如 "linux/amd64"。
	Platform = unknownProperty
	// BuildComments 可用于在构建时注入与二进制关联的任意附加信息。
	BuildComments = unknownProperty
	// Name 是构建时注入的二进制名称，为空时 Print 不显示它。
	Name = unknownProperty
)

func init() {
	collectFromBuildInfo()
	collectFromRuntime()
}

// Print 打印收集到的版本信息。
func Print() {
	fmt.Print(String())
}

func Tag() string {
	if GitTag != unknownProperty {
		return GitTag
	}
	return ""
}

func String() string {
	builder := strings.Builder{}
	xprintf := func(k string, v string) {
		fmt.Fprintf(&builder, "%s:\t%s\n", k, v)
	}

	if Name != unknownProperty {
		xprintf("App Name", Name)
	}

	xprintf("Go version", GoVersion)
	xprintf("Git commit", GitCommit)
	xprintf("Commit date", GitCommitDate)

	if GitTreeState != unknownProperty {
		xprintf("Git state", GitTreeState)
	}

	if BuildDate != unknownProperty {
		xprintf("Build date", BuildDate)
	}

	if BuildComments != unknownProperty {
		xprintf("Build comments", BuildComments)
	}

	xprintf("OS/Arch", Platform)
	xprintf("Compiler", Compiler)

	if GitTag != unknownProperty {
		xprintf("Git tag", GitTag)
	}

	return builder.String()
}

// collectFromBuildInfo 尝试设置 Go module 嵌入的构建信息，已由 -ldflags 设置的值不覆盖。
func collectFromBuildInfo() {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}

	for _, kv := range info.Settings {
		switch kv.Key {
		case "vcs.revision":
			if GitCommit == unknownProperty && kv.Value != "" {
				GitCommit = kv.Value
			}
		case "vcs.time":
			if GitCommitDate == unknownProperty && kv.Value != "" {
				GitCommitDate = kv.Value
			}

		case "vcs.modified":
			if GitTreeState == unknownProperty && kv.Value == "true" {
				GitTreeState = "dirty"
			}
		}
	}
}

// collectFromRuntime 尝试设置 go runtime 嵌入的构建信息，已由 -ldflags 设置的值不覆盖。
func collectFromRuntime() {
	if GoVersion == unknownProperty {
		GoVersion = runtime.Version()
	}

	if Platform == unknownProperty {
		Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	}
}
