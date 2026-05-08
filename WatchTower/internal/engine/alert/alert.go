package alert

import (
	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type Output struct {
	logger *zap.Logger
}

func NewOutput(logger *zap.Logger) *Output {
	return &Output{logger: logger}
}

func (o *Output) Emit(alert *models.Alert, event *models.Event) {
	o.logger.Info("ALERT",
		zap.Int("rule_id", alert.RuleID),
		zap.Int("level", alert.Level),
		zap.String("title", alert.Title),
		zap.String("description", alert.Description),
		zap.String("agent_id", alert.AgentID),
		zap.String("event_type", event.Type),
	)
}
