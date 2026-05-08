//go:build windows

package updater

import (
	"fmt"
	"os"
	"os/exec"
)

// execReplace on Windows cannot use execve(2), so it starts the updated binary
// as a new process and exits the current one.  The Windows Service Control
// Manager will restart the service according to its recovery settings.
func execReplace(path string) error {
	cmd := exec.Command(path, os.Args[1:]...)
	cmd.Env = os.Environ()
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start updated binary: %w", err)
	}
	os.Exit(0)
	return nil // unreachable
}
