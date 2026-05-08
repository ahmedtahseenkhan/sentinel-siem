// Package license provides RSA-signed license key functionality.
//
// A license encodes: customer ID, expiry date, maximum agent count, and a set
// of feature flags. It is signed with a 2048-bit RSA private key held by the
// vendor; the corresponding public key is embedded in each binary at build time.
//
// License format (base64url-encoded JSON envelope):
//
//	{
//	  "payload": "<base64url(JSON claims)>",
//	  "sig":     "<base64url(RSA-PSS SHA-256 signature of payload bytes)>"
//	}
//
// Claims JSON:
//
//	{
//	  "customer_id":  "acme-corp",
//	  "issued_at":    1711900000,      // Unix seconds
//	  "expires_at":   1743436000,      // Unix seconds
//	  "max_agents":   500,
//	  "features":     ["compliance", "threatintel", "sigma", "autoupdate"]
//	}
//
// Usage (verifier):
//
//	lic, err := license.Verify(tokenString, pubKey)
//	if err != nil { log.Fatal(err) }
//	if !lic.AllowsFeature("sigma") { ... }
//
// Usage (issuer / test):
//
//	token, err := license.Issue(claims, privKey)
package license

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// Claims holds the structured contents of a license.
type Claims struct {
	CustomerID string   `json:"customer_id"`
	IssuedAt   int64    `json:"issued_at"`
	ExpiresAt  int64    `json:"expires_at"`
	MaxAgents  int      `json:"max_agents"`
	Features   []string `json:"features"`
}

// License is a verified, decoded license.
type License struct {
	Claims
}

// Expired reports whether the license has passed its expiry date.
func (l *License) Expired() bool {
	return time.Now().Unix() > l.ExpiresAt
}

// AllowsFeature reports whether the named feature is included in the license.
func (l *License) AllowsFeature(feature string) bool {
	for _, f := range l.Features {
		if f == feature {
			return true
		}
	}
	return false
}

// AgentAllowed reports whether adding one more agent is permitted.
func (l *License) AgentAllowed(currentCount int) bool {
	if l.MaxAgents <= 0 {
		return true // unlimited
	}
	return currentCount < l.MaxAgents
}

// envelope is the signed token structure.
type envelope struct {
	Payload string `json:"payload"` // base64url-encoded claims JSON
	Sig     string `json:"sig"`     // base64url-encoded RSA-PSS signature over payload bytes
}

// Issue signs claims with privKey and returns a base64url-encoded license token.
// This function is intended for the vendor's license issuer tool.
func Issue(claims Claims, privKey *rsa.PrivateKey) (string, error) {
	if claims.CustomerID == "" {
		return "", errors.New("customer_id is required")
	}
	if claims.ExpiresAt == 0 {
		return "", errors.New("expires_at is required")
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = time.Now().Unix()
	}

	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	hash := sha256.Sum256([]byte(payloadB64))
	sig, err := rsa.SignPSS(rand.Reader, privKey, crypto.SHA256, hash[:], nil)
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}

	env := envelope{
		Payload: payloadB64,
		Sig:     base64.RawURLEncoding.EncodeToString(sig),
	}
	envJSON, err := json.Marshal(env)
	if err != nil {
		return "", fmt.Errorf("marshal envelope: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(envJSON), nil
}

// Verify parses and verifies a license token using pubKey. It returns an error
// if the signature is invalid, the token is malformed, or the license is expired.
func Verify(token string, pubKey *rsa.PublicKey) (*License, error) {
	envJSON, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		return nil, fmt.Errorf("decode token: %w", err)
	}

	var env envelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		return nil, fmt.Errorf("parse envelope: %w", err)
	}

	// Verify signature first before parsing claims (fail-fast on tampered tokens).
	sigBytes, err := base64.RawURLEncoding.DecodeString(env.Sig)
	if err != nil {
		return nil, fmt.Errorf("decode signature: %w", err)
	}
	hash := sha256.Sum256([]byte(env.Payload))
	if err := rsa.VerifyPSS(pubKey, crypto.SHA256, hash[:], sigBytes, nil); err != nil {
		return nil, fmt.Errorf("invalid license signature: %w", err)
	}

	// Decode and unmarshal claims.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(env.Payload)
	if err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("parse claims: %w", err)
	}

	lic := &License{Claims: claims}
	if lic.Expired() {
		return nil, fmt.Errorf("license expired on %s", time.Unix(claims.ExpiresAt, 0).UTC().Format(time.DateOnly))
	}
	return lic, nil
}

// LoadPublicKeyFile reads a PEM-encoded RSA public key from path.
func LoadPublicKeyFile(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read pubkey: %w", err)
	}
	return ParsePublicKeyPEM(data)
}

// ParsePublicKeyPEM parses PEM-encoded RSA public key bytes.
func ParsePublicKeyPEM(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse pubkey: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key is not RSA")
	}
	return rsaPub, nil
}

// LoadPrivateKeyFile reads a PEM-encoded RSA private key from path.
// Used only by the license issuer tool.
func LoadPrivateKeyFile(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read privkey: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in private key")
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to PKCS#1
		priv2, err2 := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err2 != nil {
			return nil, fmt.Errorf("parse privkey: %w (PKCS8: %v)", err2, err)
		}
		return priv2, nil
	}
	rsaPriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rsaPriv, nil
}
