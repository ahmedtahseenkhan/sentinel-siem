package utils

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// SHA256File returns the SHA256 hash of the file at path (hex-encoded).
func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// FileHashes returns md5, sha1, sha256 of the file at path in a single pass.
// Returned values are hex-encoded and lower case. Wazuh emits all three so
// upstream rules and IoC feeds (VirusTotal, MISP) can match on any of them.
func FileHashes(path string) (md5sum, sha1sum, sha256sum string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()
	hMD5 := md5.New()
	hSHA1 := sha1.New()
	hSHA256 := sha256.New()
	w := io.MultiWriter(hMD5, hSHA1, hSHA256)
	if _, err := io.Copy(w, f); err != nil {
		return "", "", "", err
	}
	return hex.EncodeToString(hMD5.Sum(nil)),
		hex.EncodeToString(hSHA1.Sum(nil)),
		hex.EncodeToString(hSHA256.Sum(nil)), nil
}
