// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idptoken signs ES256 JWTs with the authorization dev environment's
// test IdP key (controller/hack/authz-dev/gen.sh). The key ID is the key's
// RFC 7638 thumbprint, the same one hack/authz-dev/mint puts in the JWKS the
// IdP serves. Standard library only, so the suite's module takes no JWT
// dependency for a test fixture.
package idptoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
)

// Claims are the claims a minted token carries. Groups and Org are omitted
// when empty. Extra adds top-level claims, such as nvke_roles; it can't
// replace any other claim here.
type Claims struct {
	Issuer   string
	Subject  string
	Audience string
	Groups   []string
	Org      string
	Extra    map[string]any
	TTL      time.Duration
}

// LoadKey reads a PKCS#8 or SEC 1 PEM P-256 private key.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read the test IdP key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s holds no PEM block", path)
	}
	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("%s: unsupported PEM block %q", path, block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	ec, ok := key.(*ecdsa.PrivateKey)
	if !ok || ec.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%s is not an ECDSA P-256 key", path)
	}
	return ec, nil
}

// coordinates returns the public key's X and Y, each 32 bytes.
func coordinates(pub *ecdsa.PublicKey) ([]byte, []byte, error) {
	ecdhKey, err := pub.ECDH()
	if err != nil {
		return nil, nil, err
	}
	raw := ecdhKey.Bytes() // 0x04 || X || Y
	if len(raw) != 65 {
		return nil, nil, fmt.Errorf("unexpected P-256 public key length %d", len(raw))
	}
	return raw[1:33], raw[33:], nil
}

// KeyID returns the RFC 7638 SHA-256 thumbprint of pub, hex-encoded.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	x, y, err := coordinates(pub)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding.EncodeToString
	// The required members in lexicographic order, no whitespace.
	canonical := fmt.Sprintf(`{"crv":"P-256","kty":"EC","x":%q,"y":%q}`, b64(x), b64(y))
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:]), nil
}

// Mint signs c with key. A negative TTL mints an expired token.
func Mint(key *ecdsa.PrivateKey, c Claims) (string, error) {
	if c.Issuer == "" || c.Audience == "" || c.Subject == "" {
		return "", errors.New("issuer, subject and audience are required")
	}
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		return "", err
	}
	header, err := json.Marshal(map[string]string{"alg": "ES256", "typ": "JWT", "kid": kid})
	if err != nil {
		return "", err
	}
	now := time.Now()
	claims := map[string]any{
		"iss": c.Issuer,
		"sub": c.Subject,
		"aud": c.Audience,
		"iat": now.Unix(),
		"exp": now.Add(c.TTL).Unix(),
	}
	if len(c.Groups) > 0 {
		claims["groups"] = c.Groups
	}
	if c.Org != "" {
		claims["org"] = c.Org
	}
	for name, value := range c.Extra {
		if _, ok := claims[name]; ok {
			return "", fmt.Errorf("extra claim %q replaces a claim Mint sets", name)
		}
		claims[name] = value
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	b64 := base64.RawURLEncoding.EncodeToString
	signingInput := b64(header) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	r, s, err := ecdsa.Sign(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("sign: %w", err)
	}
	// JWS ES256 is R || S, each left-padded to 32 bytes, not ASN.1.
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return signingInput + "." + b64(signature), nil
}
