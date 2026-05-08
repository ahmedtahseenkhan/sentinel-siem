package models

import (
	"context"
	"time"
)

// AgentInfo holds agent identity and metadata.
type AgentInfo struct {
	ID        string            `json:"id"`
	Version   string            `json:"version"`
	Hostname  string            `json:"hostname"`
	OS        string            `json:"os"`
	Platform  string            `json:"platform"`
	Labels    map[string]string `json:"labels"`
	StartTime time.Time         `json:"start_time"`
}

// DataPoint is a single telemetry event from a collector.
type DataPoint struct {
	Timestamp time.Time
	Type      string
	Tags      map[string]string
	Fields    map[string]interface{}
}

// Collector is the interface all telemetry collectors implement.
type Collector interface {
	Name() string
	Start(ctx context.Context) error
	Stop() error
	DataChan() <-chan DataPoint
	Interval() time.Duration
}
