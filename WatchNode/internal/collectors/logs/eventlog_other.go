//go:build !windows

package logs

import (
	"context"

	"github.com/watchnode/watchnode/internal/models"
)

func runEventLog(ctx context.Context, channels []string, dataCh chan<- models.DataPoint, stopCh <-chan struct{}) {
	_ = channels
	_ = dataCh
	select {
	case <-ctx.Done():
	case <-stopCh:
	}
}
