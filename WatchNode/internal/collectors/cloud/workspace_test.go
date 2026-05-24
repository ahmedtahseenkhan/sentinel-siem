package cloud

import "testing"

func TestFlattenWorkspaceActivity(t *testing.T) {
	item := map[string]interface{}{
		"id": map[string]interface{}{
			"time":            "2026-05-24T10:00:00.123Z",
			"uniqueQualifier": "abc",
		},
		"actor": map[string]interface{}{
			"email":      "alice@corp.com",
			"callerType": "USER",
		},
		"ipAddress": "8.8.8.8",
		"events": []interface{}{
			map[string]interface{}{
				"name": "login_success",
				"type": "login",
				"parameters": []interface{}{
					map[string]interface{}{"name": "login_type", "value": "google_password"},
				},
			},
		},
	}
	flat := flattenWorkspaceActivity(item)

	for _, c := range []struct {
		key, want string
	}{
		{"time", "2026-05-24T10:00:00.123Z"},
		{"unique_qualifier", "abc"},
		{"actor_email", "alice@corp.com"},
		{"actor_caller", "USER"},
		{"actor_ip", "8.8.8.8"},
		{"event_name", "login_success"},
		{"event_type", "login"},
	} {
		if got, _ := flat[c.key].(string); got != c.want {
			t.Errorf("%s = %q, want %q", c.key, got, c.want)
		}
	}
	// raw must round-trip the input so workload-specific rules retain access
	// to parameters[] etc.
	raw, ok := flat["raw"].(map[string]interface{})
	if !ok {
		t.Fatal("raw not preserved as map")
	}
	if _, ok := raw["events"]; !ok {
		t.Error("raw.events missing")
	}
}

func TestFlattenWorkspaceActivityEmpty(t *testing.T) {
	// No id, no actor, no events — must not panic; should return empty
	// string fields with raw set.
	flat := flattenWorkspaceActivity(map[string]interface{}{})
	if flat["time"] != "" {
		t.Errorf("empty time = %v", flat["time"])
	}
	if _, ok := flat["raw"]; !ok {
		t.Error("raw missing")
	}
}
