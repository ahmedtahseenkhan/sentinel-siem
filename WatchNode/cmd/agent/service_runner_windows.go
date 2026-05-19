//go:build windows

package main

import (
	"context"

	"github.com/watchnode/watchnode/internal/agent"
	"golang.org/x/sys/windows/svc"
)

// windowsService implements svc.Handler so the SCM can start/stop/pause us.
type windowsService struct {
	run func(ctx context.Context)
}

func (ws *windowsService) Execute(args []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start the agent in background.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ws.run(ctx)
	}()

	status <- svc.Status{
		State:   svc.Running,
		Accepts: svc.AcceptStop | svc.AcceptShutdown,
	}

	for {
		select {
		case c := <-req:
			switch c.Cmd {
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				cancel()
				<-done
				return false, 0
			default:
				// Ignore other control codes.
			}
		case <-done:
			// Agent exited on its own — return non-zero so SCM triggers restart.
			return false, 1
		}
	}
}

// runAsService wraps the agent run function in the Windows SCM protocol.
// Called from main() when the process is started by the SCM.
func runAsService(runFn func(ctx context.Context)) error {
	return svc.Run(agent.ServiceName(), &windowsService{run: runFn})
}
