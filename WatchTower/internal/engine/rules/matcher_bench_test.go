package rules

import (
	"fmt"
	"testing"
	"time"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

// buildSyntheticMatcher creates a Matcher with N rules across M event types,
// half with regex fields and half with equality fields.
func buildSyntheticMatcher(numRules, numTypes int) *Matcher {
	m := NewMatcher(zap.NewNop())
	for i := 0; i < numRules; i++ {
		eventType := fmt.Sprintf("type.%d", i%numTypes)
		r := models.Rule{
			ID:    9000 + i,
			Level: 10,
			Match: models.RuleMatch{
				Type:   eventType,
				Fields: map[string]models.FieldMatch{},
			},
			Enabled: true,
		}
		if i%2 == 0 {
			r.Match.Fields["field_a"] = models.FieldMatch{Regex: "(?i)(suspicious|malware|backdoor)"}
		} else {
			r.Match.Fields["field_a"] = models.FieldMatch{Equals: "normal"}
		}
		_ = m.Add(r)
	}
	return m
}

func BenchmarkMatcher_3356Rules(b *testing.B) {
	m := buildSyntheticMatcher(3356, 50)
	event := &models.Event{
		Type: "type.0",
		Fields: map[string]interface{}{
			"field_a": "suspicious activity detected",
			"field_b": "extra-data",
		},
		Timestamp: time.Now().UnixMilli(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(event)
	}
}

func BenchmarkMatcher_TypeIsolation(b *testing.B) {
	// Verify type indexing skips irrelevant rules: rule for type.0 should NOT
	// touch rules for type.49.
	m := buildSyntheticMatcher(3356, 50)
	event := &models.Event{
		Type:      "type.42",
		Fields:    map[string]interface{}{"field_a": "normal"},
		Timestamp: time.Now().UnixMilli(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(event)
	}
}

func BenchmarkMatcher_UnknownType(b *testing.B) {
	// Event type that no rule matches — should be very fast (only wildcards).
	m := buildSyntheticMatcher(3356, 50)
	event := &models.Event{
		Type:      "type.unknown",
		Fields:    map[string]interface{}{"field_a": "normal"},
		Timestamp: time.Now().UnixMilli(),
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = m.Match(event)
	}
}
