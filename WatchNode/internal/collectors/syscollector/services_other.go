//go:build !windows

package syscollector

import "time"

func (c *Collector) collectServices(ts time.Time) {}
