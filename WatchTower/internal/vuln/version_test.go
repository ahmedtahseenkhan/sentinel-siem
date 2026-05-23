package vuln

import "testing"

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		// Basic.
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "1.0.1", -1},
		{"1.0.1", "1.0.0", 1},
		{"2", "10", -1},  // numeric, not lexicographic
		{"10", "2", 1},

		// Dpkg epoch.
		{"1:2.0", "2.0", 1},   // epoch beats no-epoch
		{"1:2.0", "1:2.0", 0},
		{"1:1.0", "2:0.1", -1},

		// Rpm release suffix.
		{"2.4.18-1.el8", "2.4.18", 1},          // release present > absent
		{"2.4.18-1.el8", "2.4.18-2.el8", -1},   // release ordered
		{"1.1.1k-1ubuntu5", "1.1.1k", 1},       // ubuntu release suffix

		// Debian tilde (pre-release sorts BEFORE).
		{"1.0~rc1", "1.0", -1},
		{"1.0~rc1", "1.0~rc2", -1},
		{"1.0~beta", "1.0~rc1", -1},

		// Mixed segments.
		{"1.0a", "1.0", 1},  // letter after digit > nothing
		{"1.0a", "1.0b", -1},

		// CVE-realistic openssl example: 1.1.1k vs 1.1.1k-1ubuntu5
		// (the second must NOT count as "below 1.1.1k" or backport patches
		// would be ignored as vulnerable).
		{"1.1.1k-1ubuntu5", "1.1.1k", 1},
	}
	for _, c := range cases {
		got := compareVersions(c.a, c.b)
		if got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestMatchVendorDisambiguation(t *testing.T) {
	db := NewDatabase(nil)
	db.AddBulk([]Vulnerability{
		{
			CVEID:        "CVE-2099-0001",
			Vendor:       "apache",
			PackageName:  "tomcat",
			AffectedMin:  "9.0.0",
			MinInclusive: true,
			AffectedMax:  "9.0.50",
			MaxInclusive: true,
			Severity:     "HIGH",
		},
	})

	// Same product name, different vendor — must not match.
	if got := db.MatchVendor("eclipse", "tomcat", "9.0.20"); len(got) != 0 {
		t.Errorf("eclipse:tomcat should not match apache CVE, got %d", len(got))
	}
	// Correct vendor + in-range version — must match.
	if got := db.MatchVendor("apache", "tomcat", "9.0.20"); len(got) != 1 {
		t.Errorf("apache:tomcat 9.0.20 should match CVE, got %d", len(got))
	}
	// Below range — must not match.
	if got := db.MatchVendor("apache", "tomcat", "8.5.0"); len(got) != 0 {
		t.Errorf("apache:tomcat 8.5.0 should be below range, got %d", len(got))
	}
	// Above range (exclusive upper would matter, here MaxInclusive=true, so 9.0.51 is above).
	if got := db.MatchVendor("apache", "tomcat", "9.0.51"); len(got) != 0 {
		t.Errorf("apache:tomcat 9.0.51 should be above range, got %d", len(got))
	}
	// Empty vendor on either side falls back to product-only matching.
	if got := db.MatchVendor("", "tomcat", "9.0.20"); len(got) != 1 {
		t.Errorf("empty vendor should match by product alone, got %d", len(got))
	}
}
