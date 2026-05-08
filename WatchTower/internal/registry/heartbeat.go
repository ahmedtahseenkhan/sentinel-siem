package registry

import "time"

const (
	DefaultHeartbeatCheckInterval = 30 * time.Second
	DefaultHeartbeatTimeout       = 2 * time.Minute
)
