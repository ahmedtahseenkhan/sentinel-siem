package vuln

import (
	"sync"

	"github.com/watchtower/watchtower/internal/models"
	"go.uber.org/zap"
)

type Scanner struct {
	logger *zap.Logger
	db     *Database
	mu     sync.RWMutex
}

func NewScanner(logger *zap.Logger) *Scanner {
	return &Scanner{
		logger: logger,
		db:     NewDatabase(logger),
	}
}

// LoadDatabase reads a persisted vulnerability database from disk.
func (s *Scanner) LoadDatabase(path string) error {
	return s.db.Load(path)
}

// UpdateDatabase fetches fresh data from feeds, merges it, and saves to disk.
func (s *Scanner) UpdateDatabase(dbPath, feedURL string) error {
	if err := s.db.Update(feedURL); err != nil {
		return err
	}
	return s.db.Save(dbPath)
}

// CheckPackageEvent satisfies the engine.VulnChecker interface.
// It scans a single package extracted from a syscollector.packages event and
// returns zero or more vulnerability events.
func (s *Scanner) CheckPackageEvent(agentID, name, version, arch string) []models.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Scan(agentID, []PackageInfo{{Name: name, Version: version, Arch: arch}})
}

func (s *Scanner) Scan(agentID string, packages []PackageInfo) []models.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []models.Event
	for _, pkg := range packages {
		vulns := s.db.Match(pkg.Name, pkg.Version)
		for _, v := range vulns {
			results = append(results, models.Event{
				Type:    "vulnerability",
				AgentID: agentID,
				Fields: map[string]interface{}{
					"package_name":    pkg.Name,
					"package_version": pkg.Version,
					"cve_id":          v.CVEID,
					"severity":        v.Severity,
					"description":     v.Description,
					"cvss_score":      v.CVSSScore,
					"fixed_version":   v.FixedVersion,
				},
			})
		}
	}
	return results
}

type PackageInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}
