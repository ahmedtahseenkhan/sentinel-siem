// Package updater implements a background auto-update mechanism for the
// WatchNode agent.  It periodically fetches a version manifest from the
// configured update server, compares the advertised version with the running
// binary's version, and — when a newer release is available — downloads the
// replacement binary, verifies its SHA-256 digest, atomically swaps the
// executable on disk, and re-executes itself in-place.
//
// Security properties:
//   - The downloaded binary is written to a temp file on the same filesystem,
//     so the final rename(2) is atomic.
//   - SHA-256 of the download is checked against the manifest before the file
//     is made executable.  If the digest doesn't match the temp file is
//     discarded and the update is aborted.
//   - Pre-release versions are only applied when AllowPrerelease is true.
//   - All HTTP requests carry a User-Agent and respect a 60-second timeout.
//
// Usage:
//
//	u := updater.New(cfg, currentVersion, logger)
//	go u.Start(ctx) // blocks until ctx is cancelled
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"go.uber.org/zap"
)

// Config controls auto-update behaviour.
type Config struct {
	// Enabled must be true for any update checks to run.
	Enabled bool `yaml:"enabled"`
	// UpdateServerURL is the base URL serving the version manifest and binaries.
	// Example: "https://updates.watchnode.io"
	UpdateServerURL string `yaml:"update_server_url"`
	// CheckInterval is a Go duration string (default "24h").
	CheckInterval string `yaml:"check_interval"`
	// AllowPrerelease, when true, allows pre-release versions to be installed.
	AllowPrerelease bool `yaml:"allow_prerelease"`
}

// VersionManifest is the JSON document served at
// {UpdateServerURL}/watchnode/{os}/{arch}/version.json
type VersionManifest struct {
	Version    string `json:"version"`     // semver string, e.g. "1.2.3"
	Prerelease bool   `json:"prerelease"`  // true for -rc/-beta/-alpha builds
	SHA256     string `json:"sha256"`      // hex-encoded SHA-256 of the binary
	DownloadURL string `json:"download_url"` // full URL to the binary
}

// Updater performs periodic version checks and in-place upgrades.
type Updater struct {
	cfg     Config
	current string // running version, e.g. "0.1.0"
	logger  *zap.Logger
	client  *http.Client
}

// New creates an Updater.  currentVersion is compared against the manifest.
func New(cfg Config, currentVersion string, logger *zap.Logger) *Updater {
	return &Updater{
		cfg:     cfg,
		current: currentVersion,
		logger:  logger,
		client: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Start begins the periodic update check loop.  It blocks until ctx is cancelled.
// Call in a goroutine.
func (u *Updater) Start(ctx context.Context) {
	interval, err := time.ParseDuration(u.cfg.CheckInterval)
	if err != nil || interval <= 0 {
		interval = 24 * time.Hour
	}
	u.logger.Info("auto-updater started",
		zap.String("current_version", u.current),
		zap.Duration("check_interval", interval),
	)

	// Check immediately on start-up, then on the interval.
	u.checkAndApply(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			u.checkAndApply(ctx)
		}
	}
}

// CheckOnce performs a single version check and applies an update if available.
// Safe to call from tests.
func (u *Updater) CheckOnce(ctx context.Context) error {
	return u.checkAndApply(ctx)
}

func (u *Updater) checkAndApply(ctx context.Context) error {
	manifest, err := u.fetchManifest(ctx)
	if err != nil {
		u.logger.Warn("update check failed", zap.Error(err))
		return err
	}

	if manifest.Prerelease && !u.cfg.AllowPrerelease {
		u.logger.Debug("skipping pre-release version",
			zap.String("available", manifest.Version))
		return nil
	}

	if !isNewer(manifest.Version, u.current) {
		u.logger.Debug("no update available",
			zap.String("current", u.current),
			zap.String("latest", manifest.Version))
		return nil
	}

	u.logger.Info("update available",
		zap.String("current", u.current),
		zap.String("latest", manifest.Version),
	)

	if err := u.downloadAndApply(ctx, manifest); err != nil {
		u.logger.Error("update failed", zap.Error(err))
		return err
	}
	// downloadAndApply calls execReplace which replaces the current process;
	// code below this point only runs in error paths where execReplace fails.
	return nil
}

// fetchManifest retrieves the version manifest from the update server.
func (u *Updater) fetchManifest(ctx context.Context) (*VersionManifest, error) {
	base := strings.TrimRight(u.cfg.UpdateServerURL, "/")
	url := fmt.Sprintf("%s/watchnode/%s/%s/version.json", base, runtime.GOOS, runtime.GOARCH)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "WatchNode/"+u.current)

	resp, err := u.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch manifest: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("manifest server returned %d", resp.StatusCode)
	}

	var m VersionManifest
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64*1024)).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode manifest: %w", err)
	}
	if m.Version == "" || m.SHA256 == "" || m.DownloadURL == "" {
		return nil, fmt.Errorf("manifest is missing required fields")
	}
	return &m, nil
}

// downloadAndApply downloads the new binary, verifies its digest, atomically
// replaces the on-disk executable, and re-execs the process.
func (u *Updater) downloadAndApply(ctx context.Context, m *VersionManifest) error {
	execPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable path: %w", err)
	}
	execPath, err = filepath.EvalSymlinks(execPath)
	if err != nil {
		return fmt.Errorf("resolve symlinks: %w", err)
	}

	// Download to a temp file on the same filesystem so rename is atomic.
	tmpFile, err := os.CreateTemp(filepath.Dir(execPath), ".watchnode-update-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		// Best-effort cleanup of temp file on failure.
		os.Remove(tmpPath)
	}()

	if err := u.downloadBinary(ctx, m.DownloadURL, tmpFile); err != nil {
		tmpFile.Close()
		return err
	}
	tmpFile.Close()

	// Verify digest.
	digest, err := sha256File(tmpPath)
	if err != nil {
		return fmt.Errorf("hash temp file: %w", err)
	}
	expected := strings.ToLower(m.SHA256)
	if digest != expected {
		return fmt.Errorf("sha256 mismatch: got %s, want %s", digest, expected)
	}

	// Mark executable.
	if err := os.Chmod(tmpPath, 0o755); err != nil {
		return fmt.Errorf("chmod: %w", err)
	}

	// Atomic rename over the running binary.
	if err := os.Rename(tmpPath, execPath); err != nil {
		return fmt.Errorf("rename: %w", err)
	}

	u.logger.Info("update applied, restarting",
		zap.String("version", m.Version),
		zap.String("path", execPath),
	)

	return execReplace(execPath)
}

func (u *Updater) downloadBinary(ctx context.Context, url string, dst *os.File) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "WatchNode/"+u.current)

	resp, err := u.client.Do(req)
	if err != nil {
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download server returned %d", resp.StatusCode)
	}

	if _, err := io.Copy(dst, resp.Body); err != nil {
		return fmt.Errorf("write binary: %w", err)
	}
	return nil
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// isNewer returns true if candidate is strictly newer than current.
// Both strings are expected to be semver without the leading "v".
// Falls back to simple string inequality for non-semver values.
func isNewer(candidate, current string) bool {
	if candidate == current {
		return false
	}
	cv := parseSemver(candidate)
	cr := parseSemver(current)
	for i := 0; i < 3; i++ {
		if cv[i] > cr[i] {
			return true
		}
		if cv[i] < cr[i] {
			return false
		}
	}
	return false
}

func parseSemver(v string) [3]int {
	v = strings.TrimPrefix(v, "v")
	parts := strings.SplitN(v, ".", 3)
	var out [3]int
	for i := 0; i < len(parts) && i < 3; i++ {
		// Strip pre-release suffix (e.g. "1-rc1" → 1)
		p := strings.FieldsFunc(parts[i], func(r rune) bool {
			return r == '-' || r == '+'
		})
		if len(p) > 0 {
			fmt.Sscanf(p[0], "%d", &out[i])
		}
	}
	return out
}
