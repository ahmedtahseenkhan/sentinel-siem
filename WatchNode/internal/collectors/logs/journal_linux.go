//go:build linux

package logs

import (
	"context"
	"time"

	"github.com/watchnode/watchnode/internal/models"
)

func runJournal(ctx context.Context, units []string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	// Stub: use systemd journal API (e.g. github.com/coreos/go-systemd/v22/journal or sdjournal)
	// For now emit a placeholder so the collector compiles.
	_ = units
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-stopCh:
			return
		case <-ticker.C:
			select {
			case dataCh <- models.DataPoint{
				Timestamp: time.Now(),
				Type:      "log.journal",
				Fields:    map[string]interface{}{"message": "journal collector stub"},
				Tags:      map[string]string{"source": "journal"},
			}:
			default:
			}
		}
	}
}
