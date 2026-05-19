package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
)

const (
	integrityFileName = "config.sha256"
	integrityInterval = 60 * time.Second
)

// ConfigIntegrityChecker monitors the agent config file for unexpected changes
// at runtime. On first run it records the SHA-256 of the config; on subsequent
// checks it compares. A mismatch is logged as a security alert and emitted as a
// DataPoint so the SOC can investigate potential tamper attempts.
type ConfigIntegrityChecker struct {
	configPath    string
	storedHash    string
	hashStorePath string
	logger        Logger
	emitFn        func(dp interface{}) // duck-typed to avoid import cycle; caller passes a func(models.DataPoint)
}

// NewConfigIntegrityChecker creates a checker for the given config path.
// hashDir is the directory where the reference hash is stored (defaults to the
// config file's directory when empty).
func NewConfigIntegrityChecker(configPath, hashDir string, logger Logger) (*ConfigIntegrityChecker, error) {
	if hashDir == "" {
		hashDir = filepath.Dir(configPath)
	}
	c := &ConfigIntegrityChecker{
		configPath:    configPath,
		hashStorePath: filepath.Join(hashDir, integrityFileName),
		logger:        logger,
	}

	current, err := hashFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("integrity: hash config: %w", err)
	}

	stored, err := loadHashFile(c.hashStorePath)
	if err != nil || stored == "" {
		// First run — record baseline.
		if err := saveHashFile(c.hashStorePath, current); err != nil {
			logger.Warn("integrity: could not save baseline hash", zap.Error(err))
		}
		c.storedHash = current
		logger.Info("config integrity baseline recorded",
			zap.String("config", configPath),
			zap.String("sha256", current),
		)
	} else {
		c.storedHash = stored
		if stored != current {
			logger.Warn("CONFIG INTEGRITY MISMATCH at startup — config was modified since last run",
				zap.String("config", configPath),
				zap.String("expected_sha256", stored),
				zap.String("current_sha256", current),
			)
		}
	}
	return c, nil
}

// RunPeriodicCheck starts a blocking loop that checks the config file hash
// every integrityInterval. Call in a goroutine. Logs a WARNING and calls
// alertFn on any mismatch. alertFn may be nil.
func (c *ConfigIntegrityChecker) RunPeriodicCheck(stopCh <-chan struct{}, alertFn func(path, expected, current string)) {
	ticker := time.NewTicker(integrityInterval)
	defer ticker.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-ticker.C:
			current, err := hashFile(c.configPath)
			if err != nil {
				c.logger.Warn("integrity: could not hash config", zap.Error(err))
				continue
			}
			if current != c.storedHash {
				c.logger.Warn("CONFIG INTEGRITY ALERT — config file modified unexpectedly",
					zap.String("config", c.configPath),
					zap.String("expected_sha256", c.storedHash),
					zap.String("current_sha256", current),
					zap.Time("detected_at", time.Now()),
				)
				if alertFn != nil {
					alertFn(c.configPath, c.storedHash, current)
				}
				// Update stored hash so we alert once per change, not every tick.
				c.storedHash = current
				_ = saveHashFile(c.hashStorePath, current)
			}
		}
	}
}

// UpdateBaseline records the current config hash as the new trusted baseline.
// Call this after a deliberate config update so the checker doesn't fire.
func (c *ConfigIntegrityChecker) UpdateBaseline() error {
	current, err := hashFile(c.configPath)
	if err != nil {
		return err
	}
	c.storedHash = current
	return saveHashFile(c.hashStorePath, current)
}

func hashFile(path string) (string, error) {
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

func loadHashFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	s := string(data)
	// Strip newline
	if len(s) > 0 && s[len(s)-1] == '\n' {
		s = s[:len(s)-1]
	}
	return s, nil
}

func saveHashFile(path, hash string) error {
	return os.WriteFile(path, []byte(hash+"\n"), 0600)
}
