//go:build !linux

package audit

import "context"

// Start is a no-op on non-Linux platforms. Whodata attribution on Windows
// flows through eventlog 4663 events; macOS has no equivalent native source.
func (c *Collector) Start(ctx context.Context) error {
	<-c.stopCh
	return nil
}
