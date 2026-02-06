//go:build darwin

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func IsRoot() bool {
	return os.Geteuid() == 0
}

func RunMeElevated(extraArgs ...string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// For macOS, we use osascript to run with admin privileges
	// We run it in background using & to avoid blocking, but osascript itself waits for the command if we don't handle it
	// However, do shell script usually waits.
	// We want to detach.
	cmdStr := fmt.Sprintf("'%s' %s &>/dev/null &", exe, argsBuilder.String())

	// Escape double quotes for AppleScript string
	scriptCmd := strings.ReplaceAll(cmdStr, "\"", "\\\"")
	script := fmt.Sprintf("do shell script \"%s\" with administrator privileges", scriptCmd)

	cmd := exec.Command("osascript", "-e", script)
	return cmd.Run()
}
