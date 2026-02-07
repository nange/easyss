//go:build linux

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
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

	// Prepare arguments
	var argsBuilder strings.Builder
	for _, arg := range os.Args[1:] {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}
	for _, arg := range extraArgs {
		argsBuilder.WriteString(fmt.Sprintf("'%s' ", strings.ReplaceAll(arg, "'", "'\\''")))
	}

	// Capture necessary environment variables for GUI
	envMap := make(map[string]string)
	envVars := []string{"DISPLAY", "XAUTHORITY", "WAYLAND_DISPLAY", "HOME"}

	for _, key := range envVars {
		if val := os.Getenv(key); val != "" {
			envMap[key] = val
		}
	}

	// Fallback for XAUTHORITY if missing
	if _, ok := envMap["XAUTHORITY"]; !ok {
		if home, ok := envMap["HOME"]; ok {
			envMap["XAUTHORITY"] = filepath.Join(home, ".Xauthority")
		} else {
			// Try to get current user's home dir
			if homeDir, err := os.UserHomeDir(); err == nil {
				envMap["XAUTHORITY"] = filepath.Join(homeDir, ".Xauthority")
			}
		}
	}

	// Build the environment string for the command
	var envBuilder strings.Builder
	for k, v := range envMap {
		envBuilder.WriteString(fmt.Sprintf("%s='%s' ", k, v))
	}

	// Construct the command to be executed by pkexec
	// We use 'env' to set the environment variables inside the elevated context
	// Structure: pkexec env DISPLAY=... nohup exe args... >/dev/null 2>&1 &

	// Note: We use sh -c to wrap the nohup command
	// The command passed to sh -c needs to be:
	// nohup /path/to/exe args... >/dev/null 2>&1 &

	innerCmd := fmt.Sprintf("nohup '%s' %s >/dev/null 2>&1 &", exe, argsBuilder.String())

	// Now we construct the full command for pkexec
	// pkexec env VAR=val... sh -c "innerCmd"

	// We need to construct arguments for exec.Command
	// pkexec [args...]

	cmdArgs := []string{"env"}
	for k, v := range envMap {
		cmdArgs = append(cmdArgs, fmt.Sprintf("%s=%s", k, v))
	}
	cmdArgs = append(cmdArgs, "sh", "-c", innerCmd)

	cmd := exec.Command("pkexec", cmdArgs...)
	return cmd.Run()
}
