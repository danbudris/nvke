// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/auth/authn"
	"github.com/dsx-ai-factory/nvke/auth/authz"
)

const (
	allowedAction = "getCluster"
	deniedAction  = "deleteCluster"
	opsIssuer     = "ops"
)

// fakeBackend reads the caller's tenant from the "tenant" claim, trusts the
// "operator" claim only from opsIssuer, applies the isolation check, and
// allows every action but deniedAction. It keeps the queries it was asked.
type fakeBackend struct {
	mu      sync.Mutex
	queries []authz.Query
}

func (f *fakeBackend) Authorize(_ context.Context, q authz.Query) (authz.Decision, error) {
	f.mu.Lock()
	f.queries = append(f.queries, q)
	f.mu.Unlock()

	tenant, _ := q.Principal.Claims["tenant"].(string)
	operator, _ := q.Principal.Claims["operator"].(bool)
	caller := authz.Caller{Tenant: tenant, Operator: operator && q.Principal.IssuerName == opsIssuer}
	if outcome := authz.CheckIsolation(caller, q.Resource); outcome != "" {
		return authz.Decision{Outcome: outcome, Caller: caller}, nil
	}
	if q.Action == deniedAction {
		return authz.Decision{Outcome: authz.OutcomeDeny, Caller: caller, Reasons: []string{"no-delete"}}, nil
	}
	return authz.Decision{Outcome: authz.OutcomeAllow, Caller: caller, Reasons: []string{"allow-all"}}, nil
}

func (*fakeBackend) Ready(context.Context) error { return nil }
func (*fakeBackend) Name() string                { return "fake" }

func (f *fakeBackend) lastQuery(t *testing.T) authz.Query {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	require.NotEmpty(t, f.queries, "the backend was not asked")
	return f.queries[len(f.queries)-1]
}

// principal returns a principal from issuer with subject, a tenant claim
// unless tenant is empty, and an operator claim.
func principal(issuer, subject, tenant string, operator bool) *authn.Principal {
	claims := map[string]any{"operator": operator}
	if tenant != "" {
		claims["tenant"] = tenant
	}
	return &authn.Principal{IssuerName: issuer, Subject: subject, Claims: claims}
}

var (
	inAcme   = principal("idp", "alice", "acme", false)
	noTenant = principal("idp", "nobody", "", false)
	// impostor claims to be an operator from an issuer the backend doesn't
	// trust for operators.
	impostor = principal("idp", "mallory", "acme", true)
	operator = principal(opsIssuer, "ops-1", "nvidia-ops", true)
)

func cluster(tenant string) authz.Resource {
	return authz.Resource{Type: "Cluster", ID: "c-1", Scope: authz.ScopeObject, Tenant: tenant}
}

// decisions records what a Guard counted.
type decisions struct {
	mu   sync.Mutex
	seen []string
}

func (d *decisions) record(outcome authz.Outcome, action string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.seen = append(d.seen, string(outcome)+" "+action)
}

func (d *decisions) all() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.seen...)
}

// newGuard returns a Guard over backend, and what it counts.
func newGuard(t *testing.T, backend authz.Authorizer) (*authz.Guard, *decisions) {
	t.Helper()
	client, err := authz.NewClient(backend)
	require.NoError(t, err)
	var counted decisions
	g, err := authz.NewGuard(client, slog.New(slog.DiscardHandler), counted.record)
	require.NoError(t, err)
	return g, &counted
}

// check runs one Check as p, nil for no principal.
func check(g *authz.Guard, p *authn.Principal, target authz.Target) (context.Context, error) {
	ctx := context.Background()
	if p != nil {
		ctx = authn.ContextWithPrincipal(ctx, p)
	}
	return g.Check(ctx, target)
}

func TestNewGuardRefusesANilClient(t *testing.T) {
	t.Parallel()

	_, err := authz.NewGuard(nil, nil, nil)
	require.ErrorContains(t, err, "guard requires a client")
}

func TestANilGuardRefuses(t *testing.T) {
	t.Parallel()

	var g *authz.Guard
	_, err := check(g, inAcme, authz.Target{Action: allowedAction, Resource: cluster("acme")})
	require.ErrorIs(t, err, authz.ErrDenied)
}

func TestGuardCheck(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		backend     authz.Authorizer // the fakeBackend if nil
		principal   *authn.Principal
		target      authz.Target
		wantErr     error // nil for an allow
		wantOutcome authz.Outcome
		wantCaller  authz.Caller
	}{
		{
			name: "no principal", principal: nil,
			target:  authz.Target{Action: allowedAction, Resource: cluster("acme")},
			wantErr: authz.ErrDenied, wantOutcome: authz.OutcomeError,
		},
		{
			name: "allow", principal: inAcme,
			target:      authz.Target{Action: allowedAction, Resource: cluster("acme")},
			wantOutcome: authz.OutcomeAllow, wantCaller: authz.Caller{Tenant: "acme"},
		},
		{
			name: "deny", principal: inAcme,
			target:  authz.Target{Action: deniedAction, Resource: cluster("acme")},
			wantErr: authz.ErrDenied, wantOutcome: authz.OutcomeDeny,
		},
		{
			name: "another tenant's object", principal: inAcme,
			target:  authz.Target{Action: allowedAction, Resource: cluster("globex")},
			wantErr: authz.ErrNotFound, wantOutcome: authz.OutcomeNotFound,
		},
		{
			name: "no tenant", principal: noTenant,
			target:  authz.Target{Action: allowedAction, Resource: cluster("acme")},
			wantErr: authz.ErrNoTenant, wantOutcome: authz.OutcomeNoTenant,
		},
		{
			name: "an invalid query", principal: inAcme,
			target:  authz.Target{Action: "", Resource: cluster("acme")},
			wantErr: authz.ErrDenied, wantOutcome: authz.OutcomeError,
		},
		{
			name: "a backend error", backend: &stubBackend{err: errors.New("policy store unreachable")}, principal: inAcme,
			target:  authz.Target{Action: allowedAction, Resource: cluster("acme")},
			wantErr: authz.ErrDenied, wantOutcome: authz.OutcomeError,
		},
		{
			name: "an operator on a missing object", principal: operator,
			target:  authz.Target{Action: allowedAction, Resource: cluster(""), Missing: true},
			wantErr: authz.ErrNotFound, wantOutcome: authz.OutcomeNotFound,
		},
		{
			name: "an operator on another tenant's object", principal: operator,
			target:      authz.Target{Action: allowedAction, Resource: cluster("acme")},
			wantOutcome: authz.OutcomeAllow, wantCaller: authz.Caller{Tenant: "nvidia-ops", Operator: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := tt.backend
			if backend == nil {
				backend = &fakeBackend{}
			}
			g, counted := newGuard(t, backend)
			ctx, err := check(g, tt.principal, tt.target)
			assert.Equal(t, []string{string(tt.wantOutcome) + " " + tt.target.Action}, counted.all())

			got, ok := authz.CallerFromContext(ctx)
			if tt.wantErr == nil {
				require.NoError(t, err)
				assert.True(t, ok, "an allow puts the caller on the context")
				assert.Equal(t, tt.wantCaller, got)
				return
			}
			require.ErrorIs(t, err, tt.wantErr)
			assert.False(t, ok, "a refusal puts no caller on the context")
			// A refusal is the bare sentinel; failing closed wraps ErrDenied.
			if tt.wantOutcome == authz.OutcomeError {
				assert.NotSame(t, tt.wantErr, err)
			} else {
				assert.Same(t, tt.wantErr, err)
			}
		})
	}
}

// Check asks about a missing object as an object with the requested ID, or a
// fixed valid ID for one Query.Validate would refuse, owned by a valid tenant
// that is the same for every request through one Guard, differs between
// Guards, and is none the request named.
func TestGuardCheckAsksAboutAMissingObjectInATenantNoCallerHolds(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{}
	g, _ := newGuard(t, backend)
	other, _ := newGuard(t, backend)
	// A list's scope and a caller's own tenant, to show Check replaces both.
	target := authz.Target{
		Action:   allowedAction,
		Resource: authz.Resource{Type: "Cluster", ID: "c-404", Scope: authz.ScopeList, Tenant: "acme"},
		Missing:  true,
	}

	_, err := check(g, inAcme, target)
	require.ErrorIs(t, err, authz.ErrNotFound)
	first := backend.lastQuery(t).Resource
	assert.Equal(t, "Cluster", first.Type)
	assert.Equal(t, "c-404", first.ID, "a well-formed ID is kept")
	assert.Equal(t, authz.ScopeObject, first.Scope)
	require.NoError(t, authz.CheckTenantID(first.Tenant))
	assert.NotEqual(t, "acme", first.Tenant)

	var placeholder string
	for _, id := range []string{`a"b`, strings.Repeat("c", 2049)} {
		malformed := target
		malformed.Resource.ID = id
		_, err = check(g, operator, malformed)
		require.ErrorIs(t, err, authz.ErrNotFound)
		got := backend.lastQuery(t).Resource
		assert.Equal(t, authz.Resource{Type: "Cluster", ID: got.ID, Scope: authz.ScopeObject, Tenant: first.Tenant}, got,
			"one Guard, one tenant for every missing object")
		assert.NotEqual(t, id, got.ID)
		require.NoError(t, (authz.Query{Principal: *operator, Action: allowedAction, Resource: got}).Validate())
		if placeholder == "" {
			placeholder = got.ID
		}
		assert.Equal(t, placeholder, got.ID, "every malformed ID becomes one placeholder")
	}

	_, err = check(other, operator, target)
	require.ErrorIs(t, err, authz.ErrNotFound)
	assert.NotEqual(t, first.Tenant, backend.lastQuery(t).Resource.Tenant, "each Guard draws its own")
}

// A missing object answers exactly like another tenant's object, error,
// counted outcome and log level, for every caller and action, whatever ID the
// request names. The only difference is an operator allowed on another
// tenant's object, which may read it anyway.
func TestAMissingObjectAnswersLikeAnotherTenants(t *testing.T) {
	t.Parallel()

	for name, p := range map[string]*authn.Principal{
		"a tenant caller": inAcme,
		"no tenant":       noTenant,
		"an impostor":     impostor,
		"an operator":     operator,
		"no principal":    nil,
	} {
		for _, action := range []string{allowedAction, deniedAction} {
			for idName, id := range map[string]string{
				"a well-formed ID": "c-404",
				"a quoted ID":      `a"b`,
				"an overlong ID":   strings.Repeat("c", 2049),
			} {
				t.Run(name+" "+action+" "+idName, func(t *testing.T) {
					t.Parallel()

					var logs bytes.Buffer
					client, err := authz.NewClient(&fakeBackend{})
					require.NoError(t, err)
					var counted decisions
					g, err := authz.NewGuard(client, slog.New(slog.NewJSONHandler(&logs, nil)), counted.record)
					require.NoError(t, err)

					_, otherErr := check(g, p, authz.Target{Action: action, Resource: cluster("globex")})
					otherLog := logs.String()
					logs.Reset()
					missing := authz.Resource{Type: "Cluster", ID: id}
					_, missingErr := check(g, p, authz.Target{Action: action, Resource: missing, Missing: true})
					seen := counted.all()
					require.Len(t, seen, 2)

					if p == operator && action == allowedAction {
						require.NoError(t, otherErr)
						require.ErrorIs(t, missingErr, authz.ErrNotFound)
						assert.Equal(t, []string{"allow " + action, "not_found " + action}, seen)
						return
					}
					require.Error(t, otherErr)
					assert.Equal(t, otherErr.Error(), missingErr.Error())
					assert.Equal(t, errors.Unwrap(otherErr) == nil, errors.Unwrap(missingErr) == nil, "both bare or both wrapped")
					assert.Equal(t, seen[0], seen[1])
					assert.Equal(t, logLevel(t, otherLog), logLevel(t, logs.String()))
				})
			}
		}
	}
}

// logLevel returns the level of the one record in a JSON log.
func logLevel(t *testing.T, log string) string {
	t.Helper()
	var record struct {
		Level string `json:"level"`
	}
	require.NoError(t, json.Unmarshal([]byte(log), &record), "one record: %s", log)
	return record.Level
}

// The tenant that owns a missing object stays out of the log.
func TestGuardCheckDoesNotLogTheMissingTenant(t *testing.T) {
	t.Parallel()

	backend := &fakeBackend{}
	client, err := authz.NewClient(backend)
	require.NoError(t, err)
	var logs bytes.Buffer
	g, err := authz.NewGuard(client, slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})), nil)
	require.NoError(t, err)

	_, err = check(g, inAcme, authz.Target{Action: allowedAction, Resource: cluster(""), Missing: true})
	require.ErrorIs(t, err, authz.ErrNotFound)
	assert.Contains(t, logs.String(), "refused request")
	assert.NotContains(t, logs.String(), backend.lastQuery(t).Resource.Tenant)
}
