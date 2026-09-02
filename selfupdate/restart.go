package selfupdate

import (
	"os"
	"strings"
)

// restartArgs rebuilds the original command line with daemon flags stripped
// and --daemon=false appended so the new process does not re-daemonize. Both
// the "-daemon value" and "-daemon=value" spellings are removed.
func restartArgs() []string {
	var args []string
	skipNext := false
	for _, arg := range os.Args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case arg == "-daemon" || arg == "--daemon":
			skipNext = true // drop the space-separated boolean value
		case strings.HasPrefix(arg, "-daemon=") || strings.HasPrefix(arg, "--daemon="):
		default:
			args = append(args, arg)
		}
	}
	return append(args, "--daemon=false")
}
