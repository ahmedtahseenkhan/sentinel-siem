package utils

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// GenerateAgentID returns a new random agent ID (e.g. for first-time registration).
func GenerateAgentID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AgentIDPath returns the default path for persisting the agent ID file.
func AgentIDPath(configDir string) string {
	if configDir != "" {
		return filepath.Join(configDir, "agent-id")
	}
	if custom := os.Getenv("WATCHNODE_AGENT_ID_PATH"); custom != "" {
		return custom
	}
	switch runtime.GOOS {
	case "windows":
		// Best-effort: fall back to current directory if ProgramData is unavailable.
		if pd := os.Getenv("ProgramData"); pd != "" {
			return filepath.Join(pd, "WatchNode", "agent-id")
		}
		return "agent-id"
	default:
		// Keep default writable for non-root containers when /var/lib is not writable.
		return "/tmp/watchnode/agent-id"
	}
}

// LoadOrCreateAgentID reads the agent ID from path, or creates and persists a new one.
func LoadOrCreateAgentID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		id := string(data)
		if len(id) >= 16 {
			return id, nil
		}
	}
	id, err := GenerateAgentID()
	if err != nil {
		return "", fmt.Errorf("generate agent id: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return "", fmt.Errorf("create config dir: %w", err)
	}
	if err := os.WriteFile(path, []byte(id), 0600); err != nil {
		return "", fmt.Errorf("persist agent id: %w", err)
	}
	return id, nil
}
