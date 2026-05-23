package vuln

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"sync"

	"go.uber.org/zap"
)

// Vulnerability represents a single known vulnerability.
//
// The Vendor field disambiguates products with the same name across vendors
// (apache:tomcat vs eclipse:tomcat). AffectedMin* captures the start of the
// version range so a CVE on >=2.0 <3.0 no longer false-positives on 1.x.
type Vulnerability struct {
	CVEID        string  `json:"cve_id"`
	Vendor       string  `json:"vendor,omitempty"`
	PackageName  string  `json:"package_name"`
	AffectedMin  string  `json:"affected_min_version,omitempty"`
	MinInclusive bool    `json:"min_inclusive,omitempty"`
	AffectedMax  string  `json:"affected_max_version,omitempty"`
	MaxInclusive bool    `json:"max_inclusive,omitempty"`
	FixedVersion string  `json:"fixed_version,omitempty"`
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
	// Merge by composite key (CVE, vendor, product, range). Necessary because
	// one CVE can now span multiple CPE matches, each a distinct row; keying
	// on CVEID alone would collapse them.
	key := func(v Vulnerability) string {
		return v.CVEID + "|" + v.Vendor + "|" + v.PackageName + "|" + v.AffectedMin + "|" + v.AffectedMax
	}
	existing := make(map[string]int)
	for i, v := range d.vulns {
		existing[key(v)] = i
	}
	for _, v := range allVulns {
		k := key(v)
		if idx, ok := existing[k]; ok {
			d.vulns[idx] = v
		} else {
			d.vulns = append(d.vulns, v)
			existing[k] = len(d.vulns) - 1
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
// MatchVendor is the preferred entry point when the vendor is known; this
// thin wrapper preserves the prior signature for callers that only have the
// product name.
func (d *Database) Match(packageName, version string) []Vulnerability {
	return d.MatchVendor("", packageName, version)
}

// MatchVendor scopes the lookup to a specific vendor when known. Empty
// vendor means "match any vendor for this product name" (legacy behavior).
func (d *Database) MatchVendor(vendor, packageName, version string) []Vulnerability {
	d.mu.RLock()
	defer d.mu.RUnlock()

	indices := d.index[strings.ToLower(packageName)]
	var matches []Vulnerability
	for _, idx := range indices {
		v := d.vulns[idx]

		// Vendor disambiguation: only enforce when both sides specify one.
		if vendor != "" && v.Vendor != "" &&
			!strings.EqualFold(vendor, v.Vendor) {
			continue
		}

		// Lower bound: skip when installed version is below the affected range.
		if v.AffectedMin != "" {
			cmp := compareVersions(version, v.AffectedMin)
			if cmp < 0 || (cmp == 0 && !v.MinInclusive) {
				continue
			}
		}
		// Upper bound: skip when installed version is above the affected range.
		if v.AffectedMax != "" {
			cmp := compareVersions(version, v.AffectedMax)
			if cmp > 0 || (cmp == 0 && !v.MaxInclusive) {
				continue
			}
		}
		// Fix already applied?
		if v.FixedVersion != "" && compareVersions(version, v.FixedVersion) >= 0 {
			continue
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

// compareVersions returns -1/0/+1 for a < b / a == b / a > b using a
// dpkg/rpm-compatible algorithm:
//   - Optional epoch prefix "N:" (dpkg). Missing epoch = 0.
//   - Compare upstream version up to the last '-' (rpm release suffix).
//   - Within each segment, alternate runs of digits and non-digits, comparing
//     digits numerically (leading zeros ignored) and non-digits
//     lexicographically with the special rule that '~' (tilde) sorts before
//     anything including end-of-string, used by Debian/Ubuntu for pre-release.
//   - Finally compare release suffix the same way.
//
// This replaces a naive split-on-dot parser that broke on dpkg epochs
// ("1:2.4.18"), rpm releases ("2.4.18-1.el8"), and pre-release tags
// ("1.0.0~rc1"), causing real CVEs to be missed.
func compareVersions(a, b string) int {
	epA, upA, relA := splitVersion(a)
	epB, upB, relB := splitVersion(b)
	if c := compareInt(epA, epB); c != 0 {
		return c
	}
	if c := compareVersionString(upA, upB); c != 0 {
		return c
	}
	return compareVersionString(relA, relB)
}

// splitVersion parses an optional "N:" epoch and an optional "-release" suffix.
func splitVersion(v string) (epoch int, upstream, release string) {
	if i := strings.IndexByte(v, ':'); i > 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	if j := strings.LastIndexByte(v, '-'); j >= 0 {
		upstream = v[:j]
		release = v[j+1:]
		return
	}
	upstream = v
	return
}

func compareInt(a, b int) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// compareVersionString implements the per-character dpkg algorithm.
func compareVersionString(a, b string) int {
	for {
		// Compare non-digit prefix (lexicographic, with '~' < empty < anything).
		ai, bi := 0, 0
		for ai < len(a) && !isDigit(a[ai]) {
			ai++
		}
		for bi < len(b) && !isDigit(b[bi]) {
			bi++
		}
		if c := compareNonDigit(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a, b = a[ai:], b[bi:]

		// Compare digit run numerically.
		ai, bi = 0, 0
		for ai < len(a) && isDigit(a[ai]) {
			ai++
		}
		for bi < len(b) && isDigit(b[bi]) {
			bi++
		}
		if c := compareDigits(a[:ai], b[:bi]); c != 0 {
			return c
		}
		a, b = a[ai:], b[bi:]

		if a == "" && b == "" {
			return 0
		}
	}
}

func compareNonDigit(a, b string) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var ca, cb byte
		if i < len(a) {
			ca = a[i]
		}
		if i < len(b) {
			cb = b[i]
		}
		// '~' sorts before everything else, including absence.
		oa := orderRank(ca)
		ob := orderRank(cb)
		if oa != ob {
			return compareInt(oa, ob)
		}
	}
	return 0
}

// orderRank: '~' < end-of-string < letter < digit/other-symbol.
// (Digits are handled separately as numeric runs.)
func orderRank(c byte) int {
	switch {
	case c == 0:
		return 1 // end-of-string
	case c == '~':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return 2 + int(c)
	default:
		return 1000 + int(c)
	}
}

func compareDigits(a, b string) int {
	a = strings.TrimLeft(a, "0")
	b = strings.TrimLeft(b, "0")
	if len(a) != len(b) {
		return compareInt(len(a), len(b))
	}
	return strings.Compare(a, b)
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }
