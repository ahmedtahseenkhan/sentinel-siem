//go:build !linux

package rootcheck

import "context"

// Start is a no-op on non-Linux platforms. The checks rely on /proc,
// /proc/net/tcp, and ps/ss binaries; emitting a scan_complete event here
// would falsely advertise coverage we do not have. Windows hosts get
// equivalent rootkit signal via Sysmon + the Defender / driver-load rules
// in batches 5000-5800.
func (c *Collector) Start(ctx context.Context) error {
	<-c.stopCh
	return nil
}
