// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package idptoken

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeKey(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A token the controller's verifier would reject for its shape fails every
// authz spec as a 401, which reads as an authN regression. Verify the shape
// here with the standard library.
func TestMintVerifies(t *testing.T) {
	path := writeKey(t)
	key, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Mint(key, Claims{
		Issuer: "https://idp.example/a", Subject: "alice", Audience: "https://nke.example",
		Groups: []string{"g1", "g2"}, Org: "nca-a", TTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts", len(parts))
	}

	var header map[string]string
	decodeSegment(t, parts[0], &header)
	kid, err := KeyID(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if header["alg"] != "ES256" || header["kid"] != kid || len(kid) != 64 {
		t.Fatalf("header = %v, want ES256 with kid %s", header, kid)
	}

	var claims map[string]any
	decodeSegment(t, parts[1], &claims)
	if claims["org"] != "nca-a" || claims["aud"] != "https://nke.example" {
		t.Fatalf("claims = %v", claims)
	}
	if groups, ok := claims["groups"].([]any); !ok || len(groups) != 2 {
		t.Fatalf("groups = %#v, want a two-element array", claims["groups"])
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(sig) != 64 {
		t.Fatalf("signature: %v, %d bytes", err, len(sig))
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
	if !ecdsa.Verify(&key.PublicKey, digest[:], r, s) {
		t.Fatal("signature does not verify")
	}
}

func TestMintOmitsEmptyClaims(t *testing.T) {
	path := writeKey(t)
	key, err := LoadKey(path)
	if err != nil {
		t.Fatal(err)
	}
	token, err := Mint(key, Claims{Issuer: "i", Subject: "s", Audience: "a", TTL: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	decodeSegment(t, strings.Split(token, ".")[1], &claims)
	if _, ok := claims["org"]; ok {
		t.Fatalf("org present: %v", claims)
	}
	if _, ok := claims["groups"]; ok {
		t.Fatalf("groups present: %v", claims)
	}
}

func TestMintAddsExtraClaims(t *testing.T) {
	key, err := LoadKey(writeKey(t))
	if err != nil {
		t.Fatal(err)
	}
	base := Claims{Issuer: "i", Subject: "s", Audience: "a", Org: "o", TTL: time.Minute}

	withRoles := base
	withRoles.Extra = map[string]any{"nvke_roles": []string{"writer"}}
	token, err := Mint(key, withRoles)
	if err != nil {
		t.Fatal(err)
	}
	var claims map[string]any
	decodeSegment(t, strings.Split(token, ".")[1], &claims)
	if roles, ok := claims["nvke_roles"].([]any); !ok || len(roles) != 1 || roles[0] != "writer" {
		t.Fatalf("nvke_roles = %#v", claims["nvke_roles"])
	}

	clash := base
	clash.Extra = map[string]any{"org": "other"}
	if _, err := Mint(key, clash); err == nil {
		t.Fatal("an extra claim replaced org")
	}
}

func decodeSegment(t *testing.T, segment string, into any) {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(segment)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}
