// Package regcanary plants decoy ("deception") values in autorun registry keys
// and raises a critical alert if one is modified or deleted. No legitimate
// software touches these decoys, so a change is a high-confidence signal of
// persistence tampering — malware writing/cleaning Run keys, or a wiper clearing
// autoruns. Windows-only; a no-op elsewhere.
//
// NOTE: this is a modify/delete tripwire (poll-based). Detecting a *read* of a
// decoy (e.g. cred-scrapers) would require registry object-access auditing
// (4663), which is heavier and not enabled here.
package regcanary

import (
	"sync"
	"time"

	"github.com/watchnode/watchnode/internal/agent"
	"github.com/watchnode/watchnode/internal/models"
)

const CollectorName = "registry_deception"

const fireCooldown = 30 * time.Second

// defaultKeys are planted with decoys when none are configured. HKLM Run is
// system-wide and a prime persistence target; the agent (SYSTEM) can write it.
var defaultKeys = []string{
	`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
}

// decoyValues planted under each watched key (name -> data). The data points at
// a non-existent binary, so the decoy never actually runs anything at logon.
var decoyValues = map[string]string{
	"SecurityHealthService_": `"C:\Windows\System32\sechealthsvc.exe"`,
}

// Collector implements models.Collector.
type Collector struct {
	cfg      agent.RegCanaryCollectorConfig
	interval time.Duration
	dataCh   chan models.DataPoint
	stopCh   chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	planted  map[string]string    // "key|name" -> expected data
	fired    map[string]time.Time // "key|name" -> last alert (cooldown)
}

func New(cfg agent.RegCanaryCollectorConfig) *Collector {
	return &Collector{
		cfg:      cfg,
		interval: agent.ParseDuration(cfg.Interval, 30*time.Second),
		dataCh:   make(chan models.DataPoint, 64),
		stopCh:   make(chan struct{}),
		planted:  make(map[string]string),
		fired:    make(map[string]time.Time),
	}
}

func (c *Collector) Name() string                      { return CollectorName }
func (c *Collector) Interval() time.Duration           { return c.interval }
func (c *Collector) DataChan() <-chan models.DataPoint { return c.dataCh }

func (c *Collector) keys() []string {
	if len(c.cfg.Keys) > 0 {
		return c.cfg.Keys
	}
	return defaultKeys
}

func (c *Collector) emit(typ string, fields map[string]interface{}, tags map[string]string) {
	select {
	case c.dataCh <- models.DataPoint{Timestamp: time.Now(), Type: typ, Fields: fields, Tags: tags}:
	default:
	}
}

// tamper emits one deception alert per decoy per cooldown.
func (c *Collector) tamper(keyPath, name, change string) {
	id := keyPath + "|" + name
	c.mu.Lock()
	if time.Since(c.fired[id]) < fireCooldown {
		c.mu.Unlock()
		return
	}
	c.fired[id] = time.Now()
	c.mu.Unlock()

	c.emit("registry.deception", map[string]interface{}{
		"key":        keyPath,
		"value_name": name,
		"change":     change,
		"message":    "Registry deception token " + change + ": " + keyPath + "\\" + name + " — likely persistence tampering",
	}, map[string]string{
		"category": "deception",
		"severity": "critical",
	})
}
