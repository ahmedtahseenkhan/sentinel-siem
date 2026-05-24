package cloud

import (
	"reflect"
	"sort"
	"testing"
)

func TestFlattenDefenderAlertCoreFields(t *testing.T) {
	raw := map[string]interface{}{
		"id":                 "abc-123",
		"providerAlertId":    "def-456",
		"title":              "Suspicious PowerShell",
		"description":        "Encoded PowerShell observed",
		"category":           "Execution",
		"severity":           "high",
		"status":             "new",
		"createdDateTime":    "2026-05-24T09:00:00Z",
		"lastUpdateDateTime": "2026-05-24T09:01:00Z",
		"serviceSource":      "microsoftDefenderForEndpoint",
		"detectionSource":    "antivirus",
	}
	flat := flattenDefenderAlert(raw)
	for _, c := range []struct{ key, want string }{
		{"id", "abc-123"},
		{"provider_alert", "def-456"},
		{"title", "Suspicious PowerShell"},
		{"severity", "high"},
		{"status", "new"},
		{"last_update", "2026-05-24T09:01:00Z"},
		{"service_source", "microsoftDefenderForEndpoint"},
	} {
		if got, _ := flat[c.key].(string); got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
}

func TestFlattenDefenderEvidenceSplits(t *testing.T) {
	raw := map[string]interface{}{
		"id":       "x",
		"severity": "high",
		"evidence": []interface{}{
			map[string]interface{}{
				"@odata.type": "#microsoft.graph.security.userEvidence",
				"userAccount": map[string]interface{}{"userPrincipalName": "alice@corp.com"},
			},
			map[string]interface{}{
				"@odata.type":   "#microsoft.graph.security.deviceEvidence",
				"deviceDnsName": "WIN-DESKTOP-01.corp.local",
			},
			map[string]interface{}{
				"@odata.type": "#microsoft.graph.security.ipEvidence",
				"ipAddress":   "8.8.8.8",
			},
			map[string]interface{}{
				"@odata.type": "#microsoft.graph.security.urlEvidence",
				"url":         "http://malware.example.com/x",
			},
			map[string]interface{}{
				"@odata.type": "#microsoft.graph.security.fileEvidence",
				"fileDetails": map[string]interface{}{"fileName": "evil.exe"},
			},
		},
	}
	flat := flattenDefenderAlert(raw)
	checks := map[string][]string{
		"evidence_users":   {"alice@corp.com"},
		"evidence_devices": {"WIN-DESKTOP-01.corp.local"},
		"evidence_ips":     {"8.8.8.8"},
		"evidence_urls":    {"http://malware.example.com/x"},
		"evidence_files":   {"evil.exe"},
	}
	for k, want := range checks {
		got, _ := flat[k].([]string)
		sort.Strings(got)
		sort.Strings(want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", k, got, want)
		}
	}
}

func TestFlattenDefenderEmptyEvidenceOmitted(t *testing.T) {
	// No evidence in the input — the evidence_* keys must not appear,
	// not be set to empty slices (keeps the document clean for downstream).
	raw := map[string]interface{}{"id": "x", "severity": "low"}
	flat := flattenDefenderAlert(raw)
	for _, k := range []string{"evidence_users", "evidence_devices", "evidence_files", "evidence_ips", "evidence_urls"} {
		if _, present := flat[k]; present {
			t.Errorf("%s should be omitted when no evidence", k)
		}
	}
}
