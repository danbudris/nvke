// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package idp signs tokens for the authorization dev environment's test IdP
// (hack/authz-dev). The key and the JWKS the IdP serves come from
// hack/authz-dev/gen.sh; the key ID is the key's RFC 7638 thumbprint, so a
// token minted here matches the served JWKS.
package idp

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const (
	// IssuerBase is the in-cluster URL of the test IdP; each issuer is a path under it.
	IssuerBase = "https://test-idp.nvke-authz-idp.svc"

	// DefaultKeyPath is where gen.sh writes the signing key, relative to controller/.
	DefaultKeyPath = ".local/authz-dev/signing-key.pem"
)

// Claims are the claims a minted token carries.
type Claims struct {
	Issuer  string
	Subject string
	Groups  []string
	Org     string
	// Extra adds top-level claims, such as nvke_roles. It can't replace a
	// claim Mint sets.
	Extra    map[string]any
	Audience string
	TTL      time.Duration
}

// LoadKey reads a PKCS#8 or SEC 1 PEM P-256 private key.
func LoadKey(path string) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key (run hack/authz-dev/gen.sh first): %w", err)
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

// publicJWK is the key's public half with its thumbprint as the key ID.
func publicJWK(key *ecdsa.PrivateKey) (jose.JSONWebKey, error) {
	jwk := jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ES256), Use: "sig"}
	thumb, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return jose.JSONWebKey{}, fmt.Errorf("thumbprint: %w", err)
	}
	jwk.KeyID = fmt.Sprintf("%x", thumb)
	return jwk, nil
}

// JWKS returns the JSON key set holding key's public half.
func JWKS(key *ecdsa.PrivateKey) ([]byte, error) {
	jwk, err := publicJWK(key)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{jwk}}, "", "  ")
}

// Mint signs c with key. An Issuer without a scheme is an issuer name under
// IssuerBase. An empty Subject is the first group, or "user".
func Mint(key *ecdsa.PrivateKey, c Claims) (string, error) {
	if c.Audience == "" {
		return "", errors.New("an audience is required")
	}
	jwk, err := publicJWK(key)
	if err != nil {
		return "", err
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), jwk.KeyID),
	)
	if err != nil {
		return "", fmt.Errorf("signer: %w", err)
	}

	issuer := c.Issuer
	if !strings.Contains(issuer, "://") {
		issuer = IssuerBase + "/" + issuer
	}
	subject := c.Subject
	if subject == "" {
		subject = "user"
		if len(c.Groups) > 0 {
			subject = c.Groups[0]
		}
	}
	now := time.Now()
	registered := jwt.Claims{
		Issuer:   issuer,
		Subject:  subject,
		Audience: jwt.Audience{c.Audience},
		IssuedAt: jwt.NewNumericDate(now),
		Expiry:   jwt.NewNumericDate(now.Add(c.TTL)),
	}
	private := map[string]any{}
	if len(c.Groups) > 0 {
		private["groups"] = c.Groups
	}
	if c.Org != "" {
		private["org"] = c.Org
	}
	for name, value := range c.Extra {
		if _, ok := private[name]; ok || isRegistered(name) {
			return "", fmt.Errorf("extra claim %q replaces a claim Mint sets", name)
		}
		private[name] = value
	}
	return jwt.Signed(signer).Claims(registered).Claims(private).Serialize()
}

// isRegistered reports whether name is a registered claim Mint sets.
func isRegistered(name string) bool {
	switch name {
	case "iss", "sub", "aud", "iat", "exp", "nbf", "jti":
		return true
	default:
		return false
	}
}
