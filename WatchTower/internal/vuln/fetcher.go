package vuln

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"go.uber.org/zap"
)

// FeedSource defines a vulnerability feed.
type FeedSource struct {
	Name string `yaml:"name" json:"name"`
	URL  string `yaml:"url" json:"url"`
	Type string `yaml:"type" json:"type"` // nvd, oval
}

// DefaultFeeds returns the default NVD and OVAL feed sources.
func DefaultFeeds() []FeedSource {
	return []FeedSource{
		{
			Name: "NVD-2024",
			URL:  "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2024.json.gz",
			Type: "nvd",
		},
		{
			Name: "NVD-2023",
			URL:  "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-2023.json.gz",
			Type: "nvd",
		},
	}
}

// Fetcher downloads vulnerability data from remote feeds.
type Fetcher struct {
	logger  *zap.Logger
	client  *http.Client
	cacheDir string
}

// NewFetcher creates a new feed fetcher.
func NewFetcher(logger *zap.Logger, cacheDir string) *Fetcher {
	return &Fetcher{
		logger: logger,
		client: &http.Client{Timeout: 120 * time.Second},
		cacheDir: cacheDir,
	}
}

// FetchNVD downloads and parses an NVD JSON feed.
func (f *Fetcher) FetchNVD(feed FeedSource) ([]Vulnerability, error) {
	data, err := f.downloadFeed(feed)
	if err != nil {
		return nil, err
	}

	var nvdFeed NVDFeed
	if err := json.Unmarshal(data, &nvdFeed); err != nil {
		return nil, fmt.Errorf("parse NVD feed %s: %w", feed.Name, err)
	}

	var vulns []Vulnerability
	for _, item := range nvdFeed.CVEItems {
		vulns = append(vulns, convertNVDItem(item)...)
	}
	f.logger.Info("NVD feed parsed",
		zap.String("feed", feed.Name),
		zap.Int("vulnerabilities", len(vulns)),
	)
	return vulns, nil
}

func (f *Fetcher) downloadFeed(feed FeedSource) ([]byte, error) {
	// Check cache
	cachePath := filepath.Join(f.cacheDir, feed.Name+".json")
	if info, err := os.Stat(cachePath); err == nil {
		// Use cache if less than 6 hours old
		if time.Since(info.ModTime()) < 6*time.Hour {
			return os.ReadFile(cachePath)
		}
	}

	f.logger.Info("downloading feed", zap.String("name", feed.Name), zap.String("url", feed.URL))
	resp, err := f.client.Get(feed.URL)
	if err != nil {
		return nil, fmt.Errorf("download %s: %w", feed.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download %s: status %d", feed.URL, resp.StatusCode)
	}

	var reader io.Reader = resp.Body
	if filepath.Ext(feed.URL) == ".gz" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("gunzip %s: %w", feed.URL, err)
		}
		defer gz.Close()
		reader = gz
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", feed.URL, err)
	}

	// Cache the result
	_ = os.MkdirAll(f.cacheDir, 0755)
	_ = os.WriteFile(cachePath, data, 0644)
	return data, nil
}

// NVDFeed represents the NVD JSON feed structure.
type NVDFeed struct {
	CVEItems []NVDCVEItem `json:"CVE_Items"`
}

// NVDCVEItem is a single CVE entry from the NVD.
type NVDCVEItem struct {
	CVE struct {
		CVEDataMeta struct {
			ID string `json:"ID"`
		} `json:"CVE_data_meta"`
		Description struct {
			DescriptionData []struct {
				Value string `json:"value"`
			} `json:"description_data"`
		} `json:"description"`
	} `json:"cve"`
	Impact struct {
		BaseMetricV3 struct {
			CVSSV3 struct {
				BaseScore    float64 `json:"baseScore"`
				BaseSeverity string  `json:"baseSeverity"`
			} `json:"cvssV3"`
		} `json:"baseMetricV3"`
		BaseMetricV2 struct {
			CVSSV2 struct {
				BaseScore float64 `json:"baseScore"`
			} `json:"cvssV2"`
			Severity string `json:"severity"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	Configurations struct {
		Nodes []struct {
			CPEMatch []struct {
				Vulnerable            bool   `json:"vulnerable"`
				CPE23URI              string `json:"cpe23Uri"`
				VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
				VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
				VersionStartIncluding string `json:"versionStartIncluding,omitempty"`
				VersionStartExcluding string `json:"versionStartExcluding,omitempty"`
			} `json:"cpe_match"`
		} `json:"nodes"`
	} `json:"configurations"`
}

// convertNVDItem produces one or more Vulnerability rows from a single NVD
// CVE entry. It now:
//   - emits one row per vulnerable CPE match (so different version ranges
//     for the same CVE no longer overwrite each other),
//   - captures vendor for disambiguation,
//   - captures range start/end with inclusivity,
//   - falls back to CVSSv2 when v3 is absent (most pre-2016 CVEs).
//
// Returns a slice; the caller flattens.
func convertNVDItem(item NVDCVEItem) []Vulnerability {
	id := item.CVE.CVEDataMeta.ID
	if id == "" {
		return nil
	}

	desc := ""
	if len(item.CVE.Description.DescriptionData) > 0 {
		desc = item.CVE.Description.DescriptionData[0].Value
	}

	score := item.Impact.BaseMetricV3.CVSSV3.BaseScore
	sev := item.Impact.BaseMetricV3.CVSSV3.BaseSeverity
	if score == 0 {
		score = item.Impact.BaseMetricV2.CVSSV2.BaseScore
		sev = item.Impact.BaseMetricV2.Severity
	}

	var out []Vulnerability
	for _, node := range item.Configurations.Nodes {
		for _, match := range node.CPEMatch {
			if !match.Vulnerable {
				continue
			}
			parts := parseCPE(match.CPE23URI)
			if parts.Product == "" {
				continue
			}
			v := Vulnerability{
				CVEID:       id,
				Vendor:      parts.Vendor,
				PackageName: parts.Product,
				Severity:    sev,
				Description: desc,
				CVSSScore:   score,
				AffectedOS:  cpeAffectedOS(parts.Part, parts.Vendor),
			}

			// Lower bound.
			switch {
			case match.VersionStartIncluding != "":
				v.AffectedMin = match.VersionStartIncluding
				v.MinInclusive = true
			case match.VersionStartExcluding != "":
				v.AffectedMin = match.VersionStartExcluding
				v.MinInclusive = false
			}

			// Upper bound.
			switch {
			case match.VersionEndIncluding != "":
				v.AffectedMax = match.VersionEndIncluding
				v.MaxInclusive = true
			case match.VersionEndExcluding != "":
				v.AffectedMax = match.VersionEndExcluding
				v.MaxInclusive = false
				// Excluding upper bound = fix version.
				v.FixedVersion = match.VersionEndExcluding
			}

			// If no range was given but the CPE pinned a single version,
			// use it as both bounds inclusive (avoids matching everything).
			if v.AffectedMin == "" && v.AffectedMax == "" && parts.Version != "" &&
				parts.Version != "*" && parts.Version != "-" {
				v.AffectedMin = parts.Version
				v.MinInclusive = true
				v.AffectedMax = parts.Version
				v.MaxInclusive = true
			}

			out = append(out, v)
		}
	}
	return out
}

type cpeParts struct {
	Part    string // "a" (application), "o" (operating system), "h" (hardware)
	Vendor  string
	Product string
	Version string
}

func parseCPE(cpe string) cpeParts {
	// cpe:2.3:<part>:<vendor>:<product>:<version>:...
	parts := splitN(cpe, ':', 6)
	cp := cpeParts{}
	if len(parts) >= 3 {
		cp.Part = parts[2]
	}
	if len(parts) >= 5 {
		cp.Vendor = parts[3]
		cp.Product = parts[4]
	}
	if len(parts) >= 6 {
		cp.Version = parts[5]
	}
	return cp
}

// cpeAffectedOS derives a runtime.GOOS-style OS scope from CPE part + vendor.
// Conservative: returns "" (cross-platform) unless the CPE strongly indicates
// a single OS. We don't try to scope application CPEs by vendor alone because
// many Microsoft / Apple apps run on multiple OSes (Office, Teams, Safari
// Tech Preview, etc.); only the explicit OS CPE part="o" produces a scope.
func cpeAffectedOS(part, vendor string) string {
	if part != "o" {
		return ""
	}
	v := strings.ToLower(vendor)
	switch {
	case strings.Contains(v, "microsoft"):
		return "windows"
	case strings.Contains(v, "apple"):
		return "darwin"
	default:
		// Most everything else under part=o is a Linux distro vendor
		// (redhat, canonical, debian, suse, oracle, fedoraproject, ...).
		return "linux"
	}
}

func splitN(s string, sep byte, n int) []string {
	var result []string
	start := 0
	for i := 0; i < len(s) && len(result) < n-1; i++ {
		if s[i] == sep {
			result = append(result, s[start:i])
			start = i + 1
		}
	}
	result = append(result, s[start:])
	return result
}
