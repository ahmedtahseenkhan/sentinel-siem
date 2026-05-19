//go:build !windows

package agent

// IsRunningAsService always returns false on non-Windows platforms.
func IsRunningAsService() bool { return false }
