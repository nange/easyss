//go:build windows && !without_tray

package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows/registry"
)

const (
	autoStartRunKey  = `Software\Microsoft\Windows\CurrentVersion\Run`
	autoStartValName = `Easyss`
)

func enableAutoStart() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("os.Executable: %w", err)
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer func() { _ = key.Close() }()

	if err := key.SetStringValue(autoStartValName, exe); err != nil {
		return fmt.Errorf("set registry value: %w", err)
	}

	return nil
}

func disableAutoStart() error {
	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.SET_VALUE)
	if err != nil {
		return fmt.Errorf("open registry key: %w", err)
	}
	defer func() { _ = key.Close() }()

	if err := key.DeleteValue(autoStartValName); err != nil {
		return fmt.Errorf("delete registry value: %w", err)
	}

	return nil
}

func isAutoStartEnabled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}

	key, err := registry.OpenKey(registry.CURRENT_USER, autoStartRunKey, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer func() { _ = key.Close() }()

	val, _, err := key.GetStringValue(autoStartValName)
	if err != nil {
		return false
	}

	return val == exe
}
