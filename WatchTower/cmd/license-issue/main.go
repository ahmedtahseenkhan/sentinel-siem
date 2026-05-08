// Command license-issue generates signed WatchTower license tokens.
//
// Usage:
//
//	license-issue \
//	  -privkey /path/to/license.key \
//	  -customer "acme-corp" \
//	  -agents 500 \
//	  -expires 365 \
//	  -features "compliance,threatintel,sigma,autoupdate"
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/watchtower/watchtower/internal/license"
)

func main() {
	privkeyPath := flag.String("privkey", "", "path to PEM-encoded RSA private key (required)")
	customer := flag.String("customer", "", "customer ID (required)")
	agents := flag.Int("agents", 0, "max agents (0 = unlimited)")
	expireDays := flag.Int("expires", 365, "license validity in days from now")
	features := flag.String("features", "", "comma-separated feature flags")
	genkey := flag.Bool("genkey", false, "generate a new 2048-bit RSA key pair and exit")
	flag.Parse()

	if *genkey {
		generateKeyPair()
		return
	}

	if *privkeyPath == "" || *customer == "" {
		flag.Usage()
		os.Exit(1)
	}

	privKey, err := license.LoadPrivateKeyFile(*privkeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load key: %v\n", err)
		os.Exit(1)
	}

	var featureList []string
	if *features != "" {
		for _, f := range strings.Split(*features, ",") {
			f = strings.TrimSpace(f)
			if f != "" {
				featureList = append(featureList, f)
			}
		}
	}

	claims := license.Claims{
		CustomerID: *customer,
		IssuedAt:   time.Now().Unix(),
		ExpiresAt:  time.Now().AddDate(0, 0, *expireDays).Unix(),
		MaxAgents:  *agents,
		Features:   featureList,
	}

	token, err := license.Issue(claims, privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(token)
}

func generateKeyPair() {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		fmt.Fprintf(os.Stderr, "generate key: %v\n", err)
		os.Exit(1)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal privkey: %v\n", err)
		os.Exit(1)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	if err := os.WriteFile("license.key", privPEM, 0600); err != nil {
		fmt.Fprintf(os.Stderr, "write license.key: %v\n", err)
		os.Exit(1)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal pubkey: %v\n", err)
		os.Exit(1)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile("license.pub", pubPEM, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write license.pub: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Generated license.key (private) and license.pub (public)")
	fmt.Println("Embed license.pub in your binaries. Keep license.key SECRET.")
}
