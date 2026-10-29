// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command mint signs a JWT with the local test IdP's ES256 key, for the
// authorization dev environment (hack/authz-dev).
//
//	go run ./hack/authz-dev/mint --issuer idp-a --sub alice --groups nvke-readers --org nca-a
//	go run ./hack/authz-dev/mint --jwks   # print the JWKS for the key
//
// An --issuer without a scheme is an issuer name, expanded to
// https://test-idp.nvke-authz-idp.svc/<name>.
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/dsx-ai-factory/nvke/controller/hack/authz-dev/idp"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	fs := flag.NewFlagSet("mint", flag.ContinueOnError)
	keyPath := fs.String("key", idp.DefaultKeyPath, "PEM ECDSA P-256 private key")
	printJWKS := fs.Bool("jwks", false, "print the JWKS for the key instead of a token")
	issuer := fs.String("issuer", "idp-a", "iss: a URL, or an issuer name under "+idp.IssuerBase)
	sub := fs.String("sub", "", "sub (default: the first group, or \"user\")")
	groups := fs.String("groups", "", "comma-separated groups claim (a JSON array; omitted when empty)")
	org := fs.String("org", "", "org claim (omitted when empty)")
	aud := fs.String("aud", "https://nke.tilt.local", "aud")
	ttl := fs.Duration("ttl", time.Hour, "lifetime; negative mints an expired token")
	if err := fs.Parse(args); err != nil {
		return err
	}

	key, err := idp.LoadKey(*keyPath)
	if err != nil {
		return err
	}
	if *printJWKS {
		out, err := idp.JWKS(key)
		if err != nil {
			return err
		}
		fmt.Fprintln(os.Stdout, string(out))
		return nil
	}

	token, err := idp.Mint(key, idp.Claims{
		Issuer:   *issuer,
		Subject:  *sub,
		Groups:   splitList(*groups),
		Org:      *org,
		Audience: *aud,
		TTL:      *ttl,
	})
	if err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, token)
	return nil
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
