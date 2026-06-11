package aitriage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"
)

// OllamaSummarizer is a free, self-hosted alternative to the Claude-backed
// Summarizer. It talks to any OpenAI-compatible chat-completions endpoint —
// Ollama's `/v1/chat/completions` being the primary target — so alert data
// never leaves the local network. It reuses the shared systemPrompt and
// NotableInput.prompt() from this package, and satisfies the same Triager
// contract as Summarizer.
type OllamaSummarizer struct {
	baseURL string // e.g. http://localhost:11434/v1
	model   string // e.g. llama3.1
	apiKey  string // optional; sent as Bearer if set (Ollama ignores it)
	http    *http.Client
	logger  *zap.Logger
}

// NewOllamaSummarizer builds an OpenAI-compatible summarizer. Empty baseURL
// defaults to local Ollama; empty model defaults to llama3.1; a non-positive
// timeout defaults to 60s (local models are slower than a hosted API).
func NewOllamaSummarizer(baseURL, model, apiKey string, timeout time.Duration, logger *zap.Logger) *OllamaSummarizer {
	if baseURL == "" {
		baseURL = "http://localhost:11434/v1"
	}
	if model == "" {
		model = "llama3.1"
	}
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	return &OllamaSummarizer{
		baseURL: strings.TrimRight(baseURL, "/"),
		model:   model,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: timeout},
		logger:  logger,
	}
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatRequest struct {
	Model     string        `json:"model"`
	Messages  []chatMessage `json:"messages"`
	Stream    bool          `json:"stream"`
	MaxTokens int           `json:"max_tokens,omitempty"`
}

type chatResponse struct {
	Choices []struct {
		Message chatMessage `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Summarize calls the OpenAI-compatible chat endpoint and returns the triage
// text. The http.Client timeout bounds the call.
func (s *OllamaSummarizer) Summarize(ctx context.Context, in NotableInput) (string, error) {
	body, err := json.Marshal(chatRequest{
		Model:     s.model,
		Stream:    false,
		MaxTokens: 1024,
		Messages: []chatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: in.prompt()},
		},
	})
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if s.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+s.apiKey)
	}

	resp, err := s.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("chat request: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("chat endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}

	var out chatResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", fmt.Errorf("decode response: %w", err)
	}
	if out.Error != nil && out.Error.Message != "" {
		return "", fmt.Errorf("chat endpoint error: %s", out.Error.Message)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("chat endpoint returned no choices")
	}
	summary := strings.TrimSpace(out.Choices[0].Message.Content)
	if summary == "" {
		return "", fmt.Errorf("chat endpoint returned empty content")
	}
	return summary, nil
}
