package utils

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSHA256FileKnownContent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "test.txt")
	// SHA256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
	if err := os.WriteFile(p, []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	const want = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Errorf("SHA256File mismatch:\n got: %s\nwant: %s", got, want)
	}
}

func TestSHA256FileNonexistent(t *testing.T) {
	_, err := SHA256File("/nonexistent/path/that/does/not/exist")
	if err == nil {
		t.Error("expected error for nonexistent file, got nil")
	}
}

func TestSHA256FileEmpty(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(p, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := SHA256File(p)
	if err != nil {
		t.Fatal(err)
	}
	// SHA256 of empty input
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("empty file SHA256 mismatch: got %s want %s", got, want)
	}
}
