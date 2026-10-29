// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/auth/authn"
	"github.com/dsx-ai-factory/nvke/auth/authz"
	"github.com/dsx-ai-factory/nvke/auth/authz/localbundle"
)

// newLocalBundle loads a bundle in which readers may get a cluster, no one may
// delete one, and policies apply too. Issuer "idp" reads the tenant from the
// "tenant" claim, and opsIssuer's callers are operators in tenant
// "nvidia-ops".
func newLocalBundle(t *testing.T, policies string) *localbundle.LocalBundle {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"policies.cedar": `@id("readers-may-get")
permit(principal in NVKE::Role::"reader", action == NVKE::Action::"getCluster", resource);
` + policies,
		"roles.json": `[{"uid": {"type": "NVKE::Role", "id": "reader"}, "attrs": {}, "parents": []}]`,
		"authorization.yaml": `apiVersion: auth.nvke.nvidia.com/v1alpha1
kind: AuthorizationConfiguration
operatorTenant: nvidia-ops
issuers:
  idp:
    tenant: {claim: tenant}
    claims:
      - {name: groups, value: readers, grants: [reader]}
  ops:
    tenant: {fixed: nvidia-ops}
    operators: true
    claims:
      - {name: groups, value: readers, grants: [reader]}
`,
	} {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	lb, err := localbundle.New(localbundle.Options{
		Dir:           dir,
		Issuers:       []string{"idp", opsIssuer},
		Actions:       []string{allowedAction, deniedAction},
		ResourceTypes: []string{"Cluster"},
	})
	require.NoError(t, err)
	return lb
}

// reader returns a principal from issuer in the reader role, with a tenant
// claim unless tenant is empty.
func reader(issuer, subject, tenant string) *authn.Principal {
	claims := map[string]any{"groups": "readers"}
	if tenant != "" {
		claims["tenant"] = tenant
	}
	return &authn.Principal{IssuerName: issuer, Subject: subject, Claims: claims}
}

// Through LocalBundle, a missing object answers like another tenant's object
// for every caller who isn't an operator. An operator allowed on another
// tenant's object gets not_found on a missing one.
func TestAMissingObjectAnswersLikeAnotherTenantsThroughLocalBundle(t *testing.T) {
	t.Parallel()

	backend := newLocalBundle(t, "")
	tests := []struct {
		name      string
		principal *authn.Principal
		action    string
		// wantOther and wantMissing are the outcomes counted for another
		// tenant's object and for a missing object.
		wantOther, wantMissing authz.Outcome
	}{
		{"a tenant caller, allowed", reader("idp", "alice", "acme"), allowedAction, authz.OutcomeNotFound, authz.OutcomeNotFound},
		{"a tenant caller, denied", reader("idp", "alice", "acme"), deniedAction, authz.OutcomeNotFound, authz.OutcomeNotFound},
		{"no tenant, allowed", reader("idp", "nobody", ""), allowedAction, authz.OutcomeNoTenant, authz.OutcomeNoTenant},
		{"no tenant, denied", reader("idp", "nobody", ""), deniedAction, authz.OutcomeNoTenant, authz.OutcomeNoTenant},
		// The operator tenant from an issuer that doesn't set operators.
		{"an impostor, allowed", reader("idp", "mallory", "nvidia-ops"), allowedAction, authz.OutcomeDeny, authz.OutcomeDeny},
		{"an impostor, denied", reader("idp", "mallory", "nvidia-ops"), deniedAction, authz.OutcomeDeny, authz.OutcomeDeny},
		{"an operator, allowed", reader(opsIssuer, "ops-1", ""), allowedAction, authz.OutcomeAllow, authz.OutcomeNotFound},
		{"an operator, denied", reader(opsIssuer, "ops-1", ""), deniedAction, authz.OutcomeDeny, authz.OutcomeDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g, counted := newGuard(t, backend)
			other := authz.Target{Action: tt.action, Resource: cluster("globex")}
			missing := authz.Target{Action: tt.action, Resource: authz.Resource{Type: "Cluster", ID: "c-404"}, Missing: true}
			_, otherErr := check(g, tt.principal, other)
			_, missingErr := check(g, tt.principal, missing)
			assert.Equal(t,
				[]string{string(tt.wantOther) + " " + tt.action, string(tt.wantMissing) + " " + tt.action},
				counted.all())
			if tt.wantOther == tt.wantMissing {
				assert.Same(t, otherErr, missingErr)
			}
		})
	}
}

// Policy that reads the resource ID decides a missing object as it decides
// another tenant's object with that ID, so the answer doesn't tell an operator
// whether the object exists.
func TestAMissingObjectAnswersLikeAnotherTenantsForIDSensitivePolicy(t *testing.T) {
	t.Parallel()

	backend := newLocalBundle(t, `@id("no-one-may-get-secret")
forbid(principal, action == NVKE::Action::"getCluster", resource == NVKE::Cluster::"secret");
`)
	tests := []struct {
		name      string
		principal *authn.Principal
		// want is the outcome counted for both objects.
		want authz.Outcome
	}{
		{"a tenant caller", reader("idp", "alice", "acme"), authz.OutcomeNotFound},
		{"an operator", reader(opsIssuer, "ops-1", ""), authz.OutcomeDeny},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			g, counted := newGuard(t, backend)
			secret := authz.Resource{Type: "Cluster", ID: "secret", Scope: authz.ScopeObject, Tenant: "globex"}
			other := authz.Target{Action: allowedAction, Resource: secret}
			missing := authz.Target{Action: allowedAction, Resource: authz.Resource{Type: "Cluster", ID: "secret"}, Missing: true}
			_, otherErr := check(g, tt.principal, other)
			_, missingErr := check(g, tt.principal, missing)
			want := string(tt.want) + " " + allowedAction
			assert.Equal(t, []string{want, want}, counted.all())
			assert.Same(t, otherErr, missingErr)
		})
	}
}
