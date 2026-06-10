package agent

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watchnode/watchnode/internal/models"
)

// nopLogger satisfies Logger without doing anything.
type nopLogger struct{}

func (nopLogger) Debug(string, ...Field) {}
func (nopLogger) Info(string, ...Field)  {}
func (nopLogger) Warn(string, ...Field)  {}
func (nopLogger) Error(string, ...Field) {}
func (n nopLogger) With(...Field) Logger { return n }

// flakyComm fails Register the first `failUntil` calls, then succeeds. All
// other ManagerClient methods are no-ops.
type flakyComm struct {
	failUntil int32
	calls     int32
	mu        sync.Mutex
}

func (c *flakyComm) Connect(context.Context) error { return nil }
func (c *flakyComm) Register(context.Context, *models.AgentInfo) error {
	n := atomic.AddInt32(&c.calls, 1)
	if n <= atomic.LoadInt32(&c.failUntil) {
		return fmt.Errorf("connection refused (attempt %d)", n)
	}
	return nil
}
func (c *flakyComm) SendBatch(context.Context, string, []models.DataPoint) error { return nil }
func (c *flakyComm) RunHeartbeat(context.Context, string, time.Duration)         {}
func (c *flakyComm) RunStream(context.Context, string, <-chan models.DataPoint) error {
	return nil
}
func (c *flakyComm) SetCommandHandler(func(string, []byte)) {}
func (c *flakyComm) Close() error                          { return nil }

func newTestAgent(t *testing.T, comm ManagerClient) *Agent {
	t.Helper()
	cfg := &Config{}
	cfg.Manager.Reconnect = ReconnectConfig{InitialBackoff: "1ms", MaxBackoff: "5ms"}
	a, err := New(cfg, nopLogger{}, comm)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return a
}

// TestRegisterWithRetry_EventuallyRegisters pins the fix for the e2e enrollment
// failure: a single Register attempt that loses the startup race against the
// manager's gRPC listener must NOT leave the agent unregistered forever. The
// agent has to keep retrying until the manager accepts it.
func TestRegisterWithRetry_EventuallyRegisters(t *testing.T) {
	comm := &flakyComm{failUntil: 3} // first 3 attempts fail, 4th succeeds
	a := newTestAgent(t, comm)
	a.runCtx = context.Background()

	done := make(chan struct{})
	go func() { a.registerWithRetry(); close(done) }()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("registerWithRetry did not return; agent never registered")
	}

	if got := atomic.LoadInt32(&comm.calls); got != 4 {
		t.Fatalf("Register called %d times, want 4 (3 failures + 1 success)", got)
	}
}

// TestRegisterWithRetry_StopsOnShutdown ensures the retry loop exits promptly
// when the agent is shutting down, instead of spinning forever.
func TestRegisterWithRetry_StopsOnShutdown(t *testing.T) {
	comm := &flakyComm{failUntil: 1 << 30} // never succeeds
	a := newTestAgent(t, comm)
	ctx, cancel := context.WithCancel(context.Background())
	a.runCtx = ctx

	done := make(chan struct{})
	go func() { a.registerWithRetry(); close(done) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("registerWithRetry did not stop after context cancel")
	}
}
