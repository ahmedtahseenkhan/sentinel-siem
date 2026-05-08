package utils

import (
	"runtime"
)

// OS returns the runtime GOOS (linux, windows, darwin, etc.).
func OS() string { return runtime.GOOS }

// Platform returns a human-readable platform string.
func Platform() string {
	return runtime.GOOS + "/" + runtime.GOARCH
}

// IsLinux returns true on Linux.
func IsLinux() bool { return runtime.GOOS == "linux" }

// IsWindows returns true on Windows.
func IsWindows() bool { return runtime.GOOS == "windows" }

// IsDarwin returns true on macOS.
func IsDarwin() bool { return runtime.GOOS == "darwin" }
