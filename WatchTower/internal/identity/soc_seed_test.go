package identity

import (
	"testing"

	"github.com/watchtower/watchtower/internal/models"
)

func TestSocSeedCandidates(t *testing.T) {
	users := []*models.IdentityUser{
		{SamAccount: "alice", Groups: []string{"SOC-Analysts", "Staff"}, Enabled: true},
		{SamAccount: "bob", Groups: []string{"soc-analysts"}, Enabled: false}, // case-insensitive match
		{SamAccount: "carol", Groups: []string{"Finance"}},                    // not in group
		{SamAccount: "dave", Groups: []string{"SOC-Analysts"}, Enabled: true}, // already on roster
		{SamAccount: "", Groups: []string{"SOC-Analysts"}},                    // no sam → skip
	}
	existing := map[string]bool{"dave": true}

	got := socSeedCandidates(users, "SOC-Analysts", existing)

	sams := map[string]*models.SOCEngineer{}
	for _, e := range got {
		sams[e.SamAccount] = e
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 candidates (alice, bob), got %d: %v", len(got), keysOf(sams))
	}
	if sams["alice"] == nil || sams["bob"] == nil {
		t.Fatalf("expected alice+bob, got %v", keysOf(sams))
	}
	if sams["carol"] != nil || sams["dave"] != nil {
		t.Fatal("carol (wrong group) and dave (existing) must be skipped")
	}
	if sams["alice"].Tier != 1 || sams["alice"].MaxLoad != 25 || !sams["alice"].Active {
		t.Fatalf("alice defaults wrong: %+v", sams["alice"])
	}
	if sams["bob"].Active { // bob is disabled in AD
		t.Fatal("bob should be seeded inactive (disabled in AD)")
	}
}

func keysOf(m map[string]*models.SOCEngineer) []string {
	var k []string
	for s := range m {
		k = append(k, s)
	}
	return k
}
