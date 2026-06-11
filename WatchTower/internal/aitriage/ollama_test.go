package aitriage

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func sampleInput() NotableInput {
	return NotableInput{
		EntityID: "host-9", EntityType: "agent", RiskScore: 130, Threshold: 100,
		Alerts: []AlertLine{{RuleID: 92013, Level: 12, Title: "Brute force success", When: time.Unix(1700000000, 0)}},
	}
}

func TestOllamaSummarizeHappyPath(t *testing.T) {
	var gotPath, gotAuth string
	var gotReq chatRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotReq)
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"choices":[{"message":{"role":"assistant","content":"  WHAT HAPPENED: brute force.  "}}]}`)
	}))
	defer srv.Close()

	s := NewOllamaSummarizer(srv.URL+"/v1", "qwen2.5", "secret", 5*time.Second, nil)
	out, err := s.Summarize(context.Background(), sampleInput())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "WHAT HAPPENED: brute force." {
		t.Errorf("content should be trimmed, got %q", out)
	}
	if gotPath != "/v1/chat/completions" {
		t.Errorf("unexpected path %q", gotPath)
	}
	if gotAuth != "Bearer secret" {
		t.Errorf("expected bearer auth, got %q", gotAuth)
	}
	if gotReq.Model != "qwen2.5" || gotReq.Stream {
		t.Errorf("bad request: model=%q stream=%v", gotReq.Model, gotReq.Stream)
	}
	if len(gotReq.Messages) != 2 || gotReq.Messages[0].Role != "system" || gotReq.Messages[1].Role != "user" {
		t.Errorf("expected system+user messages, got %+v", gotReq.Messages)
	}
	if !strings.Contains(gotReq.Messages[1].Content, "host-9") {
		t.Errorf("user message should carry the notable prompt, got %q", gotReq.Messages[1].Content)
	}
}

func TestOllamaSummarizeHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, "model not found")
	}))
	defer srv.Close()

	s := NewOllamaSummarizer(srv.URL+"/v1", "missing", "", time.Second, nil)
	if _, err := s.Summarize(context.Background(), sampleInput()); err == nil {
		t.Fatal("expected error on 500 response")
	}
}

func TestOllamaSummarizeNoChoices(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"choices":[]}`)
	}))
	defer srv.Close()

	s := NewOllamaSummarizer(srv.URL+"/v1", "m", "", time.Second, nil)
	if _, err := s.Summarize(context.Background(), sampleInput()); err == nil {
		t.Fatal("expected error when no choices returned")
	}
}

func TestNewOllamaSummarizerDefaults(t *testing.T) {
	s := NewOllamaSummarizer("", "", "", 0, nil)
	if s.baseURL != "http://localhost:11434/v1" {
		t.Errorf("empty baseURL should default to local Ollama, got %q", s.baseURL)
	}
	if s.model != "llama3.1" {
		t.Errorf("empty model should default to llama3.1, got %q", s.model)
	}
	if s.http.Timeout != 60*time.Second {
		t.Errorf("non-positive timeout should default to 60s, got %s", s.http.Timeout)
	}
}

func TestNewOllamaSummarizerTrimsTrailingSlash(t *testing.T) {
	s := NewOllamaSummarizer("http://host:11434/v1/", "m", "", time.Second, nil)
	if strings.HasSuffix(s.baseURL, "/") {
		t.Errorf("trailing slash should be trimmed, got %q", s.baseURL)
	}
}
