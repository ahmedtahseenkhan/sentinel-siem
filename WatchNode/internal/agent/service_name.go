package agent

// ServiceName returns the Windows service name for the agent.
// Used by the service runner to register with the SCM.
func ServiceName() string { return "SentinelWatchNode" }
