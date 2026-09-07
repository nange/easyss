package main

import (
	"os"

	"github.com/nange/easyss/v3/selfupdate"
)

// runSelfupdateSubcommand handles the "selfupdate" subcommand (check the
// latest release, and by default download and replace the running binary
// without restarting). It reports whether the subcommand was handled, in
// which case the process has already exited.
func runSelfupdateSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "selfupdate" {
		return false
	}
	os.Exit(selfupdate.RunCLICommand(os.Args[2:], selfupdateProduct()))
	return true
}
