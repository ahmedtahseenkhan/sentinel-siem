package vuln

import (
	"encoding/json"
	"os"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Vulnerability represents a single known vulnerability.
type Vulnerability struct {
	CVEID        string  `json:"cve_id"`
	PackageName  string  `json:"package_name"`
	AffectedMax  string  `json:"affected_max_version"`
	FixedVersion string  `json:"fixed_version"`
	Severity     string  `json:"severity"`
	Description  string  `json:"description"`
	CVSSScore    float64 `json:"cvss_score"`
}

// Database holds vulnerability data and supports matching against packages.
type Database struct {
	logger *zap.Logger
	mu     sync.RWMutex
	vulns  []Vulnerability
	index  map[string][]int // packageName -> indices in vulns slice
}

// NewDatabase creates a new vulnerability database.
func NewDatabase(logger *zap.Logger) *Database {
	return &Database{
		logger: logger,
		index:  make(map[string][]int),
	}
}

// Load reads vulnerability data from a JSON file on disk.
func (d *Database) Load(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			d.logger.Info("no existing vulnerability database", zap.String("path", path))
			return nil
		}
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := json.Unmarshal(data, &d.vulns); err != nil {
		return err
	}
	d.rebuildIndex()
	d.logger.Info("vulnerability database loaded",
		zap.String("path", path),
		zap.Int("entries", len(d.vulns)),
	)
	return nil
}

// Save writes the current vulnerability database to disk.
func (d *Database) Save(path string) error {
	d.mu.RLock()
	data, err := json.Marshal(d.vulns)
	d.mu.RUnlock()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// Update fetches vulnerabilities from feeds and merges into the database.
func (d *Database) Update(feedURL string) error {
	fetcher := NewFetcher(d.logger, "/var/lib/watchtower/vuln-cache")
	feeds := DefaultFeeds()
	if feedURL != "" {
		feeds = append(feeds, FeedSource{
			Name: "custom",
			URL:  feedURL,
			Type: "nvd",
		})
	}

	var allVulns []Vulnerability
	for _, feed := range feeds {
		vulns, err := fetcher.FetchNVD(feed)
		if err != nil {
			d.logger.Warn("failed to fetch feed", zap.String("name", feed.Name), zap.Error(err))
			continue
		}
		allVulns = append(allVulns, vulns...)
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	// Merge: add new CVEs, update existing
	existing := make(map[string]int)
	for i, v := range d.vulns {
		existing[v.CVEID] = i
	}
	for _, v := range allVulns {
		if idx, ok := existing[v.CVEID]; ok {
			d.vulns[idx] = v
		} else {
			d.vulns = append(d.vulns, v)
			existing[v.CVEID] = len(d.vulns) - 1
		}
	}
	d.rebuildIndex()
	d.logger.Info("vulnerability database updated",
		zap.Int("total_entries", len(d.vulns)),
		zap.Int("new_fetched", len(allVulns)),
	)
	return nil
}

// Match finds vulnerabilities for a given package name and version.
func (d *Database) Match(packageName, version string) []Vulnerability {
	d.mu.RLock()
	defer d.mu.RUnlock()

	indices := d.index[strings.ToLower(packageName)]
	var matches []Vulnerability
	for _, idx := range indices {
		v := d.vulns[idx]
		if v.AffectedMax != "" && compareVersions(version, v.AffectedMax) > 0 {
			continue // version is newer than affected max
		}
		if v.FixedVersion != "" && compareVersions(version, v.FixedVersion) >= 0 {
			continue // version is at or above fix
		}
		matches = append(matches, v)
	}
	return matches
}

// Count returns the number of vulnerabilities in the database.
func (d *Database) Count() int {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return len(d.vulns)
}

// AddBulk adds vulnerabilities in bulk and rebuilds the index.
func (d *Database) AddBulk(vulns []Vulnerability) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.vulns = append(d.vulns, vulns...)
	d.rebuildIndex()
}

func (d *Database) rebuildIndex() {
	d.index = make(map[string][]int)
	for i, v := range d.vulns {
		key := strings.ToLower(v.PackageName)
		d.index[key] = append(d.index[key], i)
	}
}

// compareVersions is a simple version comparison.
// Returns -1 if a < b, 0 if a == b, 1 if a > b.
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")

	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}

	for i := 0; i < maxLen; i++ {
		var aNum, bNum int
		if i < len(aParts) {
			aNum = parseVersionPart(aParts[i])
		}
		if i < len(bParts) {
			bNum = parseVersionPart(bParts[i])
		}
		if aNum < bNum {
			return -1
		}
		if aNum > bNum {
			return 1
		}
	}
	return 0
}

func parseVersionPart(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		} else {
			break
		}
	}
	return n
}
