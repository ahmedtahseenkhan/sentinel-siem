// Package aitriage turns a fired RBA Risk Notable and its contributing alerts
// into a plain-English triage summary for SOC analysts, using Claude.
//
// It is deliberately dependency-light (only the Anthropic SDK + zap): callers
// flatten their domain types into NotableInput, so this package never imports
// the engine, store, or models packages. The summarizer is meant to run off
// the hot alert path (in a goroutine) since each call is a network round-trip.
package aitriage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"go.uber.org/zap"
)

// AlertLine is one contributing alert, flattened for the prompt.
type AlertLine struct {
	RuleID int
	Level  int
	Title  string
	When   time.Time
}

// NotableInput is everything the summarizer needs about one fired notable.
type NotableInput struct {
	EntityID   string
	EntityType string
	RiskScore  int
	Threshold  int
	Alerts     []AlertLine
}

// Summarizer calls Claude to produce analyst-facing triage text.
type Summarizer struct {
	client  anthropic.Client
	model   anthropic.Model
	timeout time.Duration
	logger  *zap.Logger
}

// NewSummarizer builds a Summarizer. An empty model defaults to Claude Opus 4.8;
// a non-positive timeout defaults to 30s.
func NewSummarizer(apiKey, model string, timeout time.Duration, logger *zap.Logger) *Summarizer {
	m := anthropic.Model(model)
	if model == "" {
		m = anthropic.ModelClaudeOpus4_8
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Summarizer{
		client:  anthropic.NewClient(option.WithAPIKey(apiKey)),
		model:   m,
		timeout: timeout,
		logger:  logger,
	}
}

const systemPrompt = `You are a senior SOC analyst assistant inside the Sentinel SIEM.

A Risk Notable fires when an entity (a host/agent or a user) accumulates enough
risk from individual alerts to cross a threshold. You are given the notable and
the alerts that contributed to it.

Write a concise triage summary for the on-call analyst. Use exactly these three
short sections, in plain text (no markdown headers, no preamble):

WHAT HAPPENED: 1-2 sentences describing the activity in plain English.
WHY IT MATTERS: 1-2 sentences on the likely attacker objective / risk, naming a
MITRE ATT&CK tactic if one is evident.
NEXT STEP: one concrete recommended action (e.g. isolate the host, disable the
account, verify with the user, close as benign).

Be specific and grounded in the alerts provided. If the alerts look like benign
or routine activity, say so plainly rather than inventing a threat. Do not
speculate beyond the evidence. Keep the whole response under 120 words.`

// prompt renders the user-turn text describing the notable and its alerts.
func (in NotableInput) prompt() string {
	var b strings.Builder
	fmt.Fprintf(&b, "Risk Notable: entity %q (%s) reached risk score %d (threshold %d).\n",
		in.EntityID, in.EntityType, in.RiskScore, in.Threshold)
	if len(in.Alerts) == 0 {
		b.WriteString("\nNo contributing alerts were available.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "\nContributing alerts (most recent first), %d shown:\n", len(in.Alerts))
	for _, a := range in.Alerts {
		fmt.Fprintf(&b, "- [level %d, rule %d] %s (%s)\n",
			a.Level, a.RuleID, a.Title, a.When.UTC().Format(time.RFC3339))
	}
	return b.String()
}

// Summarize calls Claude and returns the triage text. The provided context is
// bounded by the configured timeout.
func (s *Summarizer) Summarize(ctx context.Context, in NotableInput) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	resp, err := s.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     s.model,
		MaxTokens: 1024,
		System:    []anthropic.TextBlockParam{{Text: systemPrompt}},
		Thinking: anthropic.ThinkingConfigParamUnion{
			OfAdaptive: &anthropic.ThinkingConfigAdaptiveParam{},
		},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(in.prompt())),
		},
	})
	if err != nil {
		return "", fmt.Errorf("claude messages.new: %w", err)
	}

	var out strings.Builder
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			out.WriteString(t.Text)
		}
	}
	summary := strings.TrimSpace(out.String())
	if summary == "" {
		return "", fmt.Errorf("claude returned no text content (stop_reason=%s)", resp.StopReason)
	}
	return summary, nil
}
