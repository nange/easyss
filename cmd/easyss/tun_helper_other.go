//go:build !darwin

package main

import (
	"fmt"
	"os"
)

// runTunHelper is a no-op on non-darwin platforms.
func runTunHelper(socketPath, device, tunIP, tunGW, localGateway,
	tunIPV6Sub, tunGWV6, serverIPV6, localGatewayV6, dnsServer string) int {
	fmt.Fprintln(os.Stderr, "tun helper is only supported on macOS")
	return 1
}
