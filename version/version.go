package version

// Ref: https://github.com/qiniu/version

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
)

const (
	unknownProperty = ""
)

// Compiler is a convenient alias for runtime.Compiler.
const Compiler = runtime.Compiler

// Version information
var (
	// GoVersion is the version of the Go toolchain used to build the binary
	// (e.g. "go1.19.2").
	// It defaults to value of runtime.Version() if not explicitly overridden.
	GoVersion = unknownProperty
	// GitCommit is the commit hash of the Git repository's HEAD at
	// build-time.
	// It defaults to the value as collected by the runtime/debug package if
	// not explicitly overridden.
	GitCommit = unknownProperty
	// GitCommitDate is GitCommit's commit date in RFC3339 format.
	// It defaults to the value as collected by the runtime/debug package if
	// not explicitly overridden.
	GitCommitDate = unknownProperty
	// GitTreeState becomes "dirty" if the source tree had local modifications
	// at build-time.
	// It stays empty otherwise and will not be shown in Print if this is the
	// case.
	GitTreeState = unknownProperty
	// GitTag is meant to be injected with the tag name associated with
	// GitCommit, by means of `go -ldflags` at build-time.
	// It stays empty otherwise and will not be shown in Print if this is the
	// case.
	GitTag = unknownProperty
	// BuildDate is meant to be injected with a string denoting the build time
	// of the binary, by means of `go -ldflags` at build-time.
	// It stays empty otherwise and will not be shown in Print if this is the
	// case.
	BuildDate = unknownProperty
	// Platform is a string in the form of "GOOS/GOARCH", e.g. "linux/amd64".
	Platform = unknownProperty
	// BuildComments can be used to associate arbitrary extra information with
	// the binary, by means of injection via `go -ldflags` at build-time.
	BuildComments = unknownProperty
	// Name is meant to be injected with the binary's intended name, by means
	// of `go -ldflags` at build-time.
	// It stays empty otherwise and will not be shown in Print if this is the
	// case.
	Name = unknownProperty
)

// This is for preventing access to the unpopulated properties.
func init() {
	collectFromBuildInfo()
	collectFromRuntime()
}

// Print prints out the collected version information.
func Print() {
	fmt.Print(String())
}

func String() string {
	builder := strings.Builder{}
	xprintf := func(k string, v string) {
		builder.WriteString(fmt.Sprintf("%s:\t%s\n", k, v))
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

// collectFromBuildInfo tries to set the build information embedded in the running binary via Go module.
// It doesn't override data if were already set by Go -ldflags.
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

// collectFromRuntime tries to set the build information embedded in the running binary via go runtime.
// It doesn't override data if were already set by Go -ldflags.
func collectFromRuntime() {
	if GoVersion == unknownProperty {
		GoVersion = runtime.Version()
	}

	if Platform == unknownProperty {
		Platform = fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH)
	}
}
