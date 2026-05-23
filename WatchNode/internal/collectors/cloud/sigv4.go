// Package cloud — AWS Signature V4 implementation.
//
// Replaces the prior placeholder that wrote a literal "Signature=placeholder"
// auth header (which every AWS service rejects with 403). Hand-rolled because
// we want to avoid pulling in the full aws-sdk-go-v2 dependency just for
// GuardDuty / S3 polling.
//
// Reference: https://docs.aws.amazon.com/general/latest/gr/sigv4_signing.html
package cloud

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// signAWSRequestV4 signs req in-place with AWS Signature V4. service is the
// AWS service code ("s3", "guardduty", "logs", ...). The request body must
// already be set; this function will read and rewind it to compute the body
// hash.
func signAWSRequestV4(req *http.Request, accessKey, secretKey, region, service string) {
	now := time.Now().UTC()
	amzDate := now.Format("20060102T150405Z")
	dateStamp := now.Format("20060102")

	req.Header.Set("X-Amz-Date", amzDate)
	if req.Header.Get("Host") == "" {
		req.Header.Set("Host", req.Host)
	}

	// 1. Canonical request.
	bodyHash := hashBody(req)
	req.Header.Set("X-Amz-Content-Sha256", bodyHash)

	canonicalURI := canonicalURIPath(req.URL.Path, service)
	canonicalQuery := canonicalQueryString(req.URL.Query())
	canonicalHeaders, signedHeaders := canonicalHeaders(req)

	canonicalRequest := strings.Join([]string{
		req.Method,
		canonicalURI,
		canonicalQuery,
		canonicalHeaders,
		signedHeaders,
		bodyHash,
	}, "\n")

	// 2. String to sign.
	credentialScope := strings.Join([]string{dateStamp, region, service, "aws4_request"}, "/")
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256",
		amzDate,
		credentialScope,
		hexHash([]byte(canonicalRequest)),
	}, "\n")

	// 3. Signing key.
	kDate := hmacSHA256([]byte("AWS4"+secretKey), []byte(dateStamp))
	kRegion := hmacSHA256(kDate, []byte(region))
	kService := hmacSHA256(kRegion, []byte(service))
	kSigning := hmacSHA256(kService, []byte("aws4_request"))

	// 4. Signature + Authorization header.
	signature := hex.EncodeToString(hmacSHA256(kSigning, []byte(stringToSign)))
	authz := "AWS4-HMAC-SHA256 " +
		"Credential=" + accessKey + "/" + credentialScope + ", " +
		"SignedHeaders=" + signedHeaders + ", " +
		"Signature=" + signature
	req.Header.Set("Authorization", authz)
}

// canonicalURIPath returns the URI path component per SigV4 rules. For most
// services the path is normalized and each segment is URI-encoded; S3 takes
// the path verbatim with one round of encoding only on reserved characters.
func canonicalURIPath(path, service string) string {
	if path == "" {
		return "/"
	}
	if service == "s3" {
		// S3 wants the path passed through, with only certain characters encoded.
		return s3EscapePath(path)
	}
	// Generic services: re-encode each segment.
	parts := strings.Split(path, "/")
	for i, p := range parts {
		parts[i] = uriEscapeSegment(p)
	}
	return strings.Join(parts, "/")
}

// s3EscapePath does the limited encoding S3 expects: keep '/', escape
// everything else through standard URL-path-segment escaping.
func s3EscapePath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '/' {
			b.WriteByte('/')
			continue
		}
		if isUnreserved(c) {
			b.WriteByte(c)
			continue
		}
		b.WriteString(uriEscapeChar(c))
	}
	return b.String()
}

func uriEscapeSegment(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			b.WriteByte(c)
		} else {
			b.WriteString(uriEscapeChar(c))
		}
	}
	return b.String()
}

func uriEscapeChar(c byte) string {
	const hexdig = "0123456789ABCDEF"
	return string([]byte{'%', hexdig[c>>4], hexdig[c&0xF]})
}

func isUnreserved(c byte) bool {
	switch {
	case c >= 'A' && c <= 'Z':
		return true
	case c >= 'a' && c <= 'z':
		return true
	case c >= '0' && c <= '9':
		return true
	case c == '-' || c == '_' || c == '.' || c == '~':
		return true
	}
	return false
}

// canonicalQueryString sorts query parameters lexicographically by key and
// URI-encodes each key and value per RFC 3986.
func canonicalQueryString(q url.Values) string {
	if len(q) == 0 {
		return ""
	}
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for j, v := range vals {
			if i > 0 || j > 0 {
				b.WriteByte('&')
			}
			b.WriteString(uriEscapeSegment(k))
			b.WriteByte('=')
			b.WriteString(uriEscapeSegment(v))
		}
	}
	return b.String()
}

// canonicalHeaders returns (canonical-header-block, signed-headers-list).
// Includes the conventional minimum: host, x-amz-date, plus any x-amz-* and
// content-type already present.
func canonicalHeaders(req *http.Request) (string, string) {
	headers := map[string]string{
		"host":         req.Host,
		"x-amz-date":   req.Header.Get("X-Amz-Date"),
	}
	if v := req.Header.Get("Content-Type"); v != "" {
		headers["content-type"] = v
	}
	if v := req.Header.Get("X-Amz-Content-Sha256"); v != "" {
		headers["x-amz-content-sha256"] = v
	}
	if v := req.Header.Get("X-Amz-Security-Token"); v != "" {
		headers["x-amz-security-token"] = v
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var hb strings.Builder
	for _, k := range keys {
		hb.WriteString(k)
		hb.WriteByte(':')
		hb.WriteString(strings.TrimSpace(collapseSpaces(headers[k])))
		hb.WriteByte('\n')
	}
	return hb.String(), strings.Join(keys, ";")
}

func collapseSpaces(s string) string {
	var b strings.Builder
	prevSpace := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '\t' {
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
			continue
		}
		prevSpace = false
		b.WriteByte(c)
	}
	return b.String()
}

// hashBody reads the request body for hashing and rewinds it so the HTTP
// transport can read it again.
func hashBody(req *http.Request) string {
	if req.Body == nil {
		return hexHash(nil)
	}
	buf, err := io.ReadAll(req.Body)
	if err != nil {
		return hexHash(nil)
	}
	req.Body = io.NopCloser(bytes.NewReader(buf))
	if req.GetBody == nil {
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(buf)), nil
		}
	}
	return hexHash(buf)
}

func hexHash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func hmacSHA256(key, data []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}
