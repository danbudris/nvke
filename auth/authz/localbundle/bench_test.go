// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package localbundle_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/auth/authn"
	"github.com/dsx-ai-factory/nvke/auth/authz"
	"github.com/dsx-ai-factory/nvke/auth/authz/localbundle"
)

// The size of the generated bundle.
const (
	benchRoles    = 200
	benchMappings = 1000
	benchActions  = 21
)

// benchBundle writes a bundle with one policy per role, each permitting a few
// actions, and benchMappings claim mappings spread over the roles.
func benchBundle(tb testing.TB) localbundle.Options {
	tb.Helper()

	actions := make([]string, benchActions)
	for i := range actions {
		actions[i] = fmt.Sprintf("action%d", i)
	}
	var roles, policies, config strings.Builder
	roles.WriteString("[")
	for i := range benchRoles {
		if i > 0 {
			roles.WriteString(",\n")
		}
		fmt.Fprintf(&roles, `{"uid": {"type": "NVKE::Role", "id": "role%d"}, "parents": []}`, i)
		fmt.Fprintf(&policies, "@id(\"policy%d\")\npermit(principal in NVKE::Role::\"role%d\", action in [%s, %s, %s], resource);\n",
			i, i, actionUID(actions, i), actionUID(actions, i+1), actionUID(actions, i+2))
	}
	roles.WriteString("]")
	config.WriteString(configHeader + "issuers:\n  idp:\n    tenant: {claim: org}\n    claims:\n")
	for i := range benchMappings {
		fmt.Fprintf(&config, "      - {name: groups, value: group%d, grants: [role%d]}\n", i, i%benchRoles)
	}

	dir := tb.TempDir()
	writeBundle(tb, dir, files{"roles.json": roles.String(), "policies.cedar": policies.String(), "authorization.yaml": config.String()})
	return localbundle.Options{Dir: dir, Issuers: []string{"idp"}, Actions: actions, ResourceTypes: []string{"Cluster"}}
}

func actionUID(actions []string, i int) string {
	return fmt.Sprintf("NVKE::Action::%q", actions[i%len(actions)])
}

func BenchmarkNew(b *testing.B) {
	opts := benchBundle(b)
	for b.Loop() {
		_, err := localbundle.New(opts)
		require.NoError(b, err)
	}
}

// Reload runs every interval, and re-reads and re-checks a bundle whose files
// haven't changed.
func BenchmarkReloadUnchanged(b *testing.B) {
	lb, err := localbundle.New(benchBundle(b))
	require.NoError(b, err)
	for b.Loop() {
		changed, err := lb.Reload()
		require.NoError(b, err)
		require.False(b, changed)
	}
}

// A caller in five groups asks about a cluster in its own tenant. The last
// group's role permits action3.
func BenchmarkAuthorize(b *testing.B) {
	lb, err := localbundle.New(benchBundle(b))
	require.NoError(b, err)
	q := authz.Query{
		Principal: authn.Principal{IssuerName: "idp", Subject: "alice", Claims: map[string]any{
			"org":    "nca-a",
			"groups": []any{"group500", "group501", "group502", "group503", "group1"},
		}},
		Action:   "action3",
		Resource: authz.Resource{Type: "Cluster", ID: "c1", Scope: authz.ScopeObject, Tenant: "nca-a"},
	}
	d, err := lb.Authorize(b.Context(), q)
	require.NoError(b, err)
	require.Equal(b, authz.OutcomeAllow, d.Outcome)

	b.Run("serial", func(b *testing.B) {
		for b.Loop() {
			if _, err := lb.Authorize(b.Context(), q); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("parallel", func(b *testing.B) {
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				if _, err := lb.Authorize(b.Context(), q); err != nil {
					b.Error(err)
					return
				}
			}
		})
	})
}
