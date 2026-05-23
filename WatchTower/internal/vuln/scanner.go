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

// CheckPackageEvent satisfies the legacy engine.VulnChecker interface.
// Equivalent to CheckPackage with an empty vendor.
func (s *Scanner) CheckPackageEvent(agentID, name, version, arch string) []models.Event {
	return s.CheckPackage(agentID, "", name, version, arch)
}

// CheckPackage scans a single package extracted from a syscollector.packages
// event and returns zero or more vulnerability events. When vendor is
// non-empty the matcher will skip rows whose CPE vendor does not match,
// preventing apache:tomcat alerts on eclipse:tomcat installs.
func (s *Scanner) CheckPackage(agentID, vendor, name, version, arch string) []models.Event {
	return s.Scan(agentID, []PackageInfo{{Vendor: vendor, Name: name, Version: version, Arch: arch}})
}

func (s *Scanner) Scan(agentID string, packages []PackageInfo) []models.Event {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var results []models.Event
	for _, pkg := range packages {
		vulns := s.db.MatchVendor(pkg.Vendor, pkg.Name, pkg.Version)
		for _, v := range vulns {
			results = append(results, models.Event{
				Type:    "vulnerability",
				AgentID: agentID,
				Fields: map[string]interface{}{
					"package_name":    pkg.Name,
					"package_vendor":  pkg.Vendor,
					"package_version": pkg.Version,
					"cve_id":          v.CVEID,
					"vuln_vendor":     v.Vendor,
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
	Vendor  string `json:"vendor,omitempty"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch,omitempty"`
}
