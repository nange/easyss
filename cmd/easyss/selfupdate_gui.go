//go:build !headless

package main

import "github.com/nange/easyss/v3/selfupdate"

// selfupdateProduct returns the release product updated by the "selfupdate"
// subcommand in tray builds.
func selfupdateProduct() selfupdate.Product {
	return selfupdate.ProductClient
}
