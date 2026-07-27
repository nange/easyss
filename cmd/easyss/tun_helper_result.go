package main

// tunHelperResult holds the results received from the TUN helper process.
type tunHelperResult struct {
	FD        int
	OriginDNS []string
}
