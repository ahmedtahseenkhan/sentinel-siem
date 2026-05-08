//go:build !windows
// +build !windows

package registry

import (
	"context"
)

// Start is a no-op on non-Windows platforms.
func (c *Collector) Start(ctx context.Context) error {
	// Windows Registry monitoring is only available on Windows.
	// Block until context is cancelled.
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.stopCh:
		return nil
	}
}
