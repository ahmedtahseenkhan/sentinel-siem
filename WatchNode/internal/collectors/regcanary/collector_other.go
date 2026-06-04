//go:build !windows
// +build !windows

package regcanary

import "context"

// Start is a no-op on non-Windows platforms (the registry is Windows-only).
func (c *Collector) Start(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

func (c *Collector) Stop() error {
	close(c.stopCh)
	return nil
}
