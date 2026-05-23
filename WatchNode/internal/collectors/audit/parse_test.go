package audit

import "testing"

func TestParseMsgHeader(t *testing.T) {
	typ, id, ts := parseMsgHeader(`type=SYSCALL msg=audit(1700000000.123:42): arch=c000003e syscall=257`)
	if typ != "SYSCALL" {
		t.Errorf("type = %q", typ)
	}
	if id != "42" {
		t.Errorf("id = %q", id)
	}
	if ts < 1.7e9 || ts > 1.71e9 {
		t.Errorf("ts = %v", ts)
	}
}

func TestMergeKVsQuotedAndBare(t *testing.T) {
	fields := map[string]interface{}{}
	mergeKVs(fields, "PATH", `type=PATH msg=audit(0:1): name="/etc/passwd" inode=12345`)
	if fields["name"] != "/etc/passwd" {
		t.Errorf("name = %v", fields["name"])
	}
	if fields["inode"] != "12345" {
		t.Errorf("inode = %v", fields["inode"])
	}
}

func TestMergeKVsHexEncoded(t *testing.T) {
	fields := map[string]interface{}{}
	// "/tmp/a b" hex-encoded
	mergeKVs(fields, "PATH", `type=PATH msg=audit(0:1): name=2F746D702F61206220`)
	if fields["name"] != "/tmp/a b " {
		t.Errorf("hex-decoded name = %q, want %q", fields["name"], "/tmp/a b ")
	}
}

func TestGroupingByID(t *testing.T) {
	g := newGrouper()
	if rec := g.feed(`type=SYSCALL msg=audit(0:1): syscall=257`); rec != nil {
		t.Fatal("first line should not complete")
	}
	if rec := g.feed(`type=PATH msg=audit(0:1): name="/etc/x"`); rec != nil {
		t.Fatal("same-id second line should not complete")
	}
	rec := g.feed(`type=SYSCALL msg=audit(0:2): syscall=2`)
	if rec == nil {
		t.Fatal("new id should flush previous record")
	}
	if rec.id != "1" {
		t.Errorf("flushed id = %q", rec.id)
	}
	if rec.fields["name"] != "/etc/x" {
		t.Errorf("flushed record missing name")
	}
}
