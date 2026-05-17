package threatintel

import "testing"

func TestExtractHostname(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"http://malicious.example.com/payload.exe", "malicious.example.com"},
		{"https://bad-actor.net/c2?x=1", "bad-actor.net"},
		{"http://bad.example.com:8080/x", "bad.example.com"},
		{"https://CAPS.Example.COM/path", "caps.example.com"},
		{"not-a-url", ""},
		{"", ""},
		{"http://bad name.com/", ""},
	}
	for _, c := range cases {
		got := extractHostname(c.in)
		if got != c.want {
			t.Errorf("extractHostname(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
