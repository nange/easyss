//go:build linux

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

	// Build arguments string safely
	// We assume simple arguments for now, but strictly we should quote them if they contain spaces
	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// Construct command to run detached
	// nohup /path/to/exe args >/dev/null 2>&1 &
	cmdStr := fmt.Sprintf("nohup '%s' %s >/dev/null 2>&1 &", exe, argsBuilder.String())

	// Use pkexec to run the shell command
	cmd := exec.Command("pkexec", "sh", "-c", cmdStr)
	return cmd.Run()
}
