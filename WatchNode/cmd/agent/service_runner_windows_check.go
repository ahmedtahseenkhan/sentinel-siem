//go:build windows

package main

import "github.com/watchnode/watchnode/internal/agent"

func isRunningAsService() bool { return agent.IsRunningAsService() }
