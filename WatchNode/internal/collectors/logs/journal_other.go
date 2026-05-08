//go:build !linux

package logs

import (
	"context"

	"github.com/watchnode/watchnode/internal/models"
)

func runJournal(ctx context.Context, units []string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	_ = units
	_ = dataCh
	select {
	case <-ctx.Done():
	case <-stopCh:
	}
}
