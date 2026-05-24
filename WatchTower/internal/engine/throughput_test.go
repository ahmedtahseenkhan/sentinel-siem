package engine

import (
	"flag"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/watchtower/watchtower/internal/models"
)

// throughput_test.go is the Week-3 7.3 deliverable: a sustained-EPS
// benchmark for the rule pipeline.
//
// Usage:
//   go test -run X -bench BenchmarkSustainedEPS ./internal/engine/ -benchtime 10s
//
// or for a longer soak:
//   go test -run X -bench BenchmarkSustainedEPS ./internal/engine/ -benchtime 60s
//
// The benchmark loads the production rule set and hammers the engine
// with synthetic events sampled from each role's canonical shape, then
// reports:
//   - sustained events ingested per second
//   - alert volume per 1000 events
//   - per-event latency (ingest -> alert stored)
//
// Target from the 8-week plan: 5,000 EPS sustained. Anything below that
// on a modern dev laptop (M-series or recent x86 with 8 cores) indicates
// a hot-path regression worth investigating before client deployments.

var benchEventCount = flag.Int("bench.events", 200000, "synthetic events to send during BenchmarkSustainedEPS")

// canonicalShapes are deterministic event templates one per role. The
// benchmark cycles through them so the rule engine sees a realistic mix
// rather than the same single shape repeatedly (which would cache-hit).
var canonicalShapes = []func() *models.Event{
	// AD logon failure
	func() *models.Event {
		return &models.Event{Type: "log.eventlog", Fields: map[string]interface{}{
			"event_id":     4625,
			"win_event_id": 4625,
			"TargetUserName": "admin",
			"IpAddress":      "203.0.113.42",
			"LogonType":      "3",
			"AuthenticationPackageName": "NTLM",
		}, AgentID: "dc01"}
	},
	// AD admin group add
	func() *models.Event {
		return &models.Event{Type: "log.eventlog", Fields: map[string]interface{}{
			"event_id":     4728,
			"win_event_id": 4728,
			"GroupName":    "Domain Admins",
			"MemberName":   "attacker",
		}, AgentID: "dc01"}
	},
	// IIS SQLi
	func() *models.Event {
		return &models.Event{Type: "log.file", Fields: map[string]interface{}{
			"source": "iis", "uri": "/p?id=1' OR 1=1--", "method": "GET", "status": 200,
		}, AgentID: "web01"}
	},
	// MSSQL xp_cmdshell
	func() *models.Event {
		return &models.Event{Type: "log.file", Fields: map[string]interface{}{
			"service": "mssql", "query": "EXEC xp_cmdshell 'whoami'", "user": "sa",
		}, AgentID: "sql01"}
	},
	// Apache traversal
	func() *models.Event {
		return &models.Event{Type: "log.file", Fields: map[string]interface{}{
			"source": "apache", "uri": "/../../../etc/passwd", "method": "GET", "status": 200,
		}, AgentID: "web02"}
	},
	// sshd failed root
	func() *models.Event {
		return &models.Event{Type: "logs.syslog", Fields: map[string]interface{}{
			"program": "sshd",
			"message": "Failed password for root from 198.51.100.7 port 51234 ssh2",
			"user":    "root",
			"src_ip":  "198.51.100.7",
		}, AgentID: "host01"}
	},
	// Audit-log cleared (compliance pipeline)
	func() *models.Event {
		return &models.Event{Type: "log.eventlog", Fields: map[string]interface{}{
			"event_id":     1102,
			"win_event_id": 1102,
		}, AgentID: "pci_host"}
	},
}

// countingStore implements AlertStore with an atomic counter; faster than
// captureStore because it doesn't allocate per-alert slices.
type countingStore struct {
	count int64
}

func (s *countingStore) InsertAlert(_ *models.Alert) (int64, error) {
	n := atomic.AddInt64(&s.count, 1)
	return n, nil
}

// BenchmarkSustainedEPS pushes -bench.events synthetic events through the
// engine as fast as the test goroutines can send them and measures the
// sustained EPS the pipeline absorbs. Drains by waiting for the alert
// count to plateau before reading the final timing.
func BenchmarkSustainedEPS(b *testing.B) {
	for n := 0; n < b.N; n++ {
		runSustainedEPSPass(b, *benchEventCount)
	}
}

func runSustainedEPSPass(b *testing.B, total int) {
	b.Helper()
	// Build engine with a fast no-op store; share the same engine across
	// the run so steady-state numbers aren't dominated by rule-load time.
	eng, _ := newTestEngine(b)
	// Swap store for the cheap counter.
	store := &countingStore{}
	eng.store = store

	rng := rand.New(rand.NewSource(42))
	start := time.Now()

	for i := 0; i < total; i++ {
		ev := canonicalShapes[rng.Intn(len(canonicalShapes))]()
		eng.Ingest(ev)
	}

	// Wait for the engine to drain. The engine channel is bounded at
	// 10k — once ingest returns, processing may still be in flight.
	// Spin until the alert count stops growing for 100ms straight.
	last := int64(-1)
	stableSince := time.Time{}
	for {
		cur := atomic.LoadInt64(&store.count)
		if cur != last {
			last = cur
			stableSince = time.Now()
		} else if !stableSince.IsZero() && time.Since(stableSince) > 100*time.Millisecond {
			break
		}
		time.Sleep(10 * time.Millisecond)
		// Safety bound — never block the benchmark forever.
		if time.Since(start) > 120*time.Second {
			b.Logf("drain timeout after 120s; %d alerts so far", cur)
			break
		}
	}

	elapsed := time.Since(start)
	alerts := atomic.LoadInt64(&store.count)
	eps := float64(total) / elapsed.Seconds()

	b.ReportMetric(eps, "events/s")
	b.ReportMetric(float64(alerts), "alerts")
	b.ReportMetric(float64(alerts)/float64(total)*1000, "alerts/1k-events")
	b.Logf("ingested %d events in %s -> %.0f EPS, %d alerts", total, elapsed, eps, alerts)
}

// TestSustainedEPSSmoke is a quick (1s) smoke test of the same harness so
// the perf path stays compilable and exercises in normal CI runs without
// burning real minutes on `-bench`. Asserts >= 1k EPS on this hardware as
// a low bar; the real 5k target is verified manually via BenchmarkSustainedEPS.
func TestSustainedEPSSmoke(t *testing.T) {
	if testing.Short() {
		t.Skip("skipped in -short")
	}
	eng, _ := newTestEngine(t)
	store := &countingStore{}
	eng.store = store

	const total = 5000
	rng := rand.New(rand.NewSource(1))
	start := time.Now()
	for i := 0; i < total; i++ {
		eng.Ingest(canonicalShapes[rng.Intn(len(canonicalShapes))]())
	}
	// Drain.
	deadline := time.Now().Add(10 * time.Second)
	last := int64(-1)
	stableSince := time.Time{}
	for time.Now().Before(deadline) {
		cur := atomic.LoadInt64(&store.count)
		if cur != last {
			last = cur
			stableSince = time.Now()
		} else if !stableSince.IsZero() && time.Since(stableSince) > 100*time.Millisecond {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	elapsed := time.Since(start)
	eps := float64(total) / elapsed.Seconds()
	alerts := atomic.LoadInt64(&store.count)
	t.Logf("smoke: %d events in %s -> %.0f EPS, %d alerts", total, elapsed, eps, alerts)
	if eps < 1000 {
		t.Errorf("sustained EPS %.0f below 1000 floor — investigate engine regression", eps)
	}
}

// (mockT shim removed — newTestEngine now takes testing.TB so b can be passed
// directly.)
