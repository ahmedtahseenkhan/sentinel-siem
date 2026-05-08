package agent

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Field is a key-value pair for structured logging.
type Field = zap.Field

// Logger interface for agent logging.
type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	With(fields ...Field) Logger
}

// ZapLogger adapts zap.Logger to Logger.
type ZapLogger struct {
	*zap.Logger
}

func (z *ZapLogger) With(fields ...Field) Logger {
	return &ZapLogger{z.Logger.With(fields...)}
}

// NewLogger creates a production logger.
func NewLogger(level string) (Logger, error) {
	var lvl zapcore.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = zapcore.InfoLevel
	}
	cfg := zap.NewProductionConfig()
	cfg.Level = zap.NewAtomicLevelAt(lvl)
	cfg.Encoding = "json"
	zl, err := cfg.Build()
	if err != nil {
		return nil, err
	}
	return &ZapLogger{zl}, nil
}

// NewLoggerDevelopment creates a development logger (console, debug).
func NewLoggerDevelopment() Logger {
	zl, _ := zap.NewDevelopment()
	return &ZapLogger{zl}
}
