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
	// Preserve all environment variables except some specific ones
	for _, env := range os.Environ() {
		k, v, ok := strings.Cut(env, "=")
		if !ok {
			continue
		}
		// Filter out some variables that might cause issues or are not needed
		if k == "_" || k == "PWD" || k == "OLDPWD" || k == "SHLVL" {
			continue
		}
		envMap[k] = v
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
		envBuilder.WriteString(fmt.Sprintf("%s='%s' ", k, strings.ReplaceAll(v, "'", "'\\''")))
	}

	// Construct the command to be executed by pkexec
	// Structure: pkexec sh -c "env_vars nohup exe args... >/dev/null 2>&1 &"

	// Note: We use sh -c to wrap the nohup command
	// The command passed to sh -c needs to be:
	// env_vars nohup /path/to/exe args... >/dev/null 2>&1 &

	innerCmd := fmt.Sprintf("%s nohup '%s' %s >/dev/null 2>&1 &", envBuilder.String(), exe, argsBuilder.String())

	// Now we construct the full command for pkexec
	// pkexec sh -c "innerCmd"

	cmdArgs := []string{"sh", "-c", innerCmd}

	cmd := exec.Command("pkexec", cmdArgs...)
	return cmd.Run()
}
