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

// 版本信息
var (
	// GoVersion 是构建该二进制所用的 Go 工具链版本（例如 "go1.19.2"）。
	// 未显式覆盖时默认为 runtime.Version() 的值。
	GoVersion = unknownProperty
	// GitCommit 是构建时 Git 仓库 HEAD 的提交哈希。
	// 未显式覆盖时默认为 runtime/debug 包收集到的值。
	GitCommit = unknownProperty
	// GitCommitDate 是 GitCommit 的提交日期，RFC3339 格式。
	// 未显式覆盖时默认为 runtime/debug 包收集到的值。
	GitCommitDate = unknownProperty
	// GitTreeState 在构建时源码树有本地修改时为 "dirty"。
	// 否则保持为空，这种情况下 Print 不会显示它。
	GitTreeState = unknownProperty
	// GitTag 旨在通过 `go -ldflags` 在构建时注入与 GitCommit 关联的标签名。
	// 否则保持为空，这种情况下 Print 不会显示它。
	GitTag = unknownProperty
	// BuildDate 旨在通过 `go -ldflags` 在构建时注入表示构建时间的字符串。
	// 否则保持为空，这种情况下 Print 不会显示它。
	BuildDate = unknownProperty
	// Platform 是 "GOOS/GOARCH" 形式的字符串，例如 "linux/amd64"。
	Platform = unknownProperty
	// BuildComments 可用于通过 `go -ldflags` 在构建时注入与二进制
	// 关联的任意附加信息。
	BuildComments = unknownProperty
	// Name 旨在通过 `go -ldflags` 在构建时注入二进制的预期名称。
	// 否则保持为空，这种情况下 Print 不会显示它。
	Name = unknownProperty
)

// 用于防止访问未填充的属性。
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

// collectFromBuildInfo 尝试设置 Go module 嵌入在运行二进制中的构建信息。
// 如果数据已由 Go -ldflags 设置，则不覆盖。
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

// collectFromRuntime 尝试设置 go runtime 嵌入在运行二进制中的构建信息。
// 如果数据已由 Go -ldflags 设置，则不覆盖。
func collectFromRuntime() {
	if GoVersion == unknownProperty {
		GoVersion = runtime.Version()
	}

	if Platform == unknownProperty {
		Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	}
}
