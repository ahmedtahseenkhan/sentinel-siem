package utils

import (
	"crypto/rand"
	"crypto/sha256"
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

// StableAgentID derives a deterministic 32-hex-char agent ID from a stable seed
// (the hostname). The same machine therefore keeps the same identity across
// reinstalls and container restarts, instead of minting a new random id each
// time — which produced "ghost" agents piling up in UEBA/RBA. Same width as
// GenerateAgentID so it's a drop-in.
func StableAgentID(seed string) string {
	sum := sha256.Sum256([]byte("watchnode-agent:" + seed))
	return hex.EncodeToString(sum[:16])
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

// LoadOrCreateAgentID reads the agent ID from path. If absent it derives a
// stable ID from seed (the hostname) so the same machine reuses the same
// identity even when the persist file is on ephemeral storage (e.g. /tmp in a
// container) or wiped by a reinstall. A random ID is used only when seed is
// empty. The result is persisted for fast lookup / manual override.
func LoadOrCreateAgentID(path, seed string) (string, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		id := string(data)
		if len(id) >= 16 {
			return id, nil
		}
	}
	var id string
	if seed != "" {
		id = StableAgentID(seed)
	} else if id, err = GenerateAgentID(); err != nil {
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
