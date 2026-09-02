package selfupdate

import (
	"os"
	"strings"
)

// restartArgs rebuilds the original command line with daemon flags stripped
// and --daemon=false appended so the new process does not re-daemonize.
func restartArgs() []string {
	var args []string
	for _, arg := range os.Args[1:] {
		if arg == "-daemon" || arg == "--daemon" ||
			strings.HasPrefix(arg, "-daemon=") || strings.HasPrefix(arg, "--daemon=") {
			continue
		}
		args = append(args, arg)
	}
	return append(args, "--daemon=false")
}
