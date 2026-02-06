//go:build !windows && !linux && !darwin

package main

import "errors"

func IsRoot() bool {
	return true // Assume root or bypass check for unsupported OS
}

func RunMeElevated(extraArgs ...string) error {
	return errors.New("unsupported operating system for elevation")
}
