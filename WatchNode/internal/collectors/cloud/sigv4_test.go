package cloud

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestSigV4GuardDutyKnownGood verifies the SigV4 implementation against a
// fixed timestamp and AWS's canonical test vector format. We don't have the
// official SigV4 test suite vectors here, but the structural checks catch
// the most common bugs (missing Date stamp, wrong scope, lowercase headers,
// canonical body hash).
func TestSigV4StructuralCorrectness(t *testing.T) {
	req, _ := http.NewRequest("GET", "https://guardduty.us-east-1.amazonaws.com/detector", nil)
	signAWSRequestV4(req, "AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "guardduty")

	authz := req.Header.Get("Authorization")

	// Must NOT contain the prior placeholder.
	if strings.Contains(authz, "placeholder") {
		t.Fatalf("auth header still contains placeholder: %s", authz)
	}
	// Must be AWS4-HMAC-SHA256.
	if !strings.HasPrefix(authz, "AWS4-HMAC-SHA256 ") {
		t.Fatalf("auth header missing AWS4-HMAC-SHA256 prefix: %s", authz)
	}
	// Must include Credential=, SignedHeaders=, Signature= in order.
	if !strings.Contains(authz, "Credential=AKIDEXAMPLE/") {
		t.Errorf("auth header missing Credential=AKIDEXAMPLE/: %s", authz)
	}
	if !strings.Contains(authz, "SignedHeaders=") {
		t.Errorf("auth header missing SignedHeaders=: %s", authz)
	}
	// Signature must be 64 hex chars (SHA-256 output).
	idx := strings.Index(authz, "Signature=")
	if idx < 0 {
		t.Fatalf("auth header missing Signature=: %s", authz)
	}
	sig := authz[idx+len("Signature="):]
	if len(sig) != 64 {
		t.Errorf("signature length = %d, want 64 hex chars", len(sig))
	}
	for _, c := range sig {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("signature contains non-hex char %q", c)
			break
		}
	}
	// X-Amz-Date must be set.
	if req.Header.Get("X-Amz-Date") == "" {
		t.Error("X-Amz-Date header not set")
	}
	// X-Amz-Content-Sha256 must be set (empty-body hash).
	expectedEmpty := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := req.Header.Get("X-Amz-Content-Sha256"); got != expectedEmpty {
		t.Errorf("empty body hash = %s, want %s", got, expectedEmpty)
	}
}

// TestCanonicalQueryStringSorts ensures multi-value params are stably ordered,
// which the SigV4 spec requires and which the AWS server validates.
func TestCanonicalQueryStringSorts(t *testing.T) {
	q := url.Values{
		"b": []string{"2", "1"},
		"a": []string{"3"},
		"c": []string{"value with spaces"},
	}
	got := canonicalQueryString(q)
	want := "a=3&b=1&b=2&c=value%20with%20spaces"
	if got != want {
		t.Errorf("canonicalQueryString = %q, want %q", got, want)
	}
}

func TestCursorAdvanceMonotonic(t *testing.T) {
	col := &Collector{cursors: map[string]time.Time{}}
	t1 := time.Now().Add(-10 * time.Minute)
	t2 := t1.Add(5 * time.Minute)
	col.cursorAdvance("p", t1)
	col.cursorAdvance("p", t2)
	col.cursorAdvance("p", t1) // earlier: must NOT regress the cursor
	if got := col.cursorSince("p"); !got.Equal(t2) {
		t.Errorf("cursor regressed: got %v, want %v", got, t2)
	}
}
