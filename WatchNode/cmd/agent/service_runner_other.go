//go:build !windows

package main

import "context"

// runAsService is a no-op on non-Windows platforms.
func runAsService(_ func(ctx context.Context)) error { return nil }

// isRunningAsService always returns false on non-Windows.
func isRunningAsService() bool { return false }
