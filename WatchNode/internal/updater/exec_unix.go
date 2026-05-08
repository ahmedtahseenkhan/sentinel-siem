//go:build !windows

package updater

import (
	"os"
	"syscall"
)

// execReplace uses execve(2) to replace the running process image with the
// updated binary.  The OS kernel keeps the same PID so service managers
// (systemd, launchd) continue tracking the process.
func execReplace(path string) error {
	return syscall.Exec(path, os.Args, os.Environ())
}
