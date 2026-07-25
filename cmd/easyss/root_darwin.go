//go:build darwin

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nange/easyss/v3/util"
)

const tunKeepaliveFile = "/tmp/easyss-tun.keepalive"

func IsRoot() bool {
	return os.Geteuid() == 0
}

func RunMeElevated(extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Resolve config file to absolute path so the elevated helper can find it
	// even though its working directory may differ.
	resolveConfigArg(&extraArgs)

	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// For macOS, we use osascript to run with admin privileges
	// We run it in background using & to avoid blocking
	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, argsBuilder.String())

	// Escape double quotes for AppleScript string
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	_, err = util.Command("osascript", "-e", script)
	return err
}

// resolveConfigArg converts any relative -c path in extraArgs to absolute.
// The elevated process may have a different working directory so a relative
// config path would fail to load.
func resolveConfigArg(extraArgs *[]string) {
	args := *extraArgs
	for i := 0; i < len(args)-1; i++ {
		if args[i] == "-c" && !filepath.IsAbs(args[i+1]) {
			if abs, err := filepath.Abs(args[i+1]); err == nil {
				args[i+1] = abs
			}
		}
	}
	*extraArgs = args
}

func writeTunKeepalive() error {
	return os.WriteFile(tunKeepaliveFile, nil, 0644)
}

func removeTunKeepalive() error {
	return os.Remove(tunKeepaliveFile)
}
