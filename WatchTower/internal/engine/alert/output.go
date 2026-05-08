package alert

import (
	"bytes"
	"encoding/json"
	"net/http"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type WebhookNotifier struct {
	logger *zap.Logger
	url    string
	client *http.Client
}

func NewWebhookNotifier(logger *zap.Logger, url string) *WebhookNotifier {
	return &WebhookNotifier{
		logger: logger,
		url:    url,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookNotifier) Notify(alert *models.Alert) error {
	if w.url == "" {
		return nil
	}
	payload, err := json.Marshal(alert)
	if err != nil {
		return err
	}
	resp, err := w.client.Post(w.url, "application/json", bytes.NewReader(payload))
	if err != nil {
		w.logger.Warn("webhook notification failed", zap.Error(err))
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		w.logger.Warn("webhook returned error", zap.Int("status", resp.StatusCode))
	}
	return nil
}
