package main

import (
	"flag"
	"os"
)

// runTunHelperSubcommand handles the internal "tun-helper" subcommand: run
// this binary as the elevated TUN helper (spawned by the tray process via
// pkexec/osascript). It reports whether the subcommand was handled, in which
// case the process has already exited.
//
// The helper is a long-running elevated process that opens the TUN device,
// sets up routing/DNS, passes the fd back to the parent via a Unix socket,
// and stays alive monitoring stdin for the parent's lifecycle signal. The
// bootstrap parameters (where to fetch the TUN config from and where to send
// the fd) cannot be derived by the helper itself — pkexec/osascript strip the
// environment — so they are passed as subcommand flags.
func runTunHelperSubcommand() bool {
	if len(os.Args) < 2 || os.Args[1] != "tun-helper" {
		return false
	}

	fs := flag.NewFlagSet("tun-helper", flag.ExitOnError)
	var tunHTTPAddr, tunFDSocket, logFile, logLevel string
	fs.StringVar(&tunHTTPAddr, "tun-http-addr", "", "HTTP address of the parent process to fetch config from")
	fs.StringVar(&tunFDSocket, "tun-fd-socket", "", "Unix socket path for fd passing to parent")
	fs.StringVar(&logFile, "log-file", "", "log file path")
	fs.StringVar(&logLevel, "log-level", "", "log level (debug, info, warn, error)")
	_ = fs.Parse(os.Args[2:])

	os.Exit(runTunHelper(tunHTTPAddr, tunFDSocket, logFile, logLevel))
	return true
}
