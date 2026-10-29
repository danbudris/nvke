// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz_test

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/auth/authn"
	authzlib "github.com/dsx-ai-factory/nvke/auth/authz"

	"github.com/dsx-ai-factory/nvke/controller/api"
	"github.com/dsx-ai-factory/nvke/controller/internal/authz"
	"github.com/dsx-ai-factory/nvke/controller/internal/db"
)

// testBundle is a bundle with readers, writers and operators.
var testBundle = map[string]string{
	"roles.json": `[
  {"uid": {"type": "NVKE::Role", "id": "reader"}, "parents": []},
  {"uid": {"type": "NVKE::Role", "id": "writer"}, "parents": [{"type": "NVKE::Role", "id": "reader"}]}
]`,
	"policies.cedar": `
@id("readers-read")
permit(principal in NVKE::Role::"reader", action in [
  NVKE::Action::"getCluster", NVKE::Action::"listClusters", NVKE::Action::"listReleases",
  NVKE::Action::"getNodePool", NVKE::Action::"getNodeSet", NVKE::Action::"getNode"
], resource);

@id("writers-write")
permit(principal in NVKE::Role::"writer", action in [NVKE::Action::"deleteCluster", NVKE::Action::"createNodePool"], resource);
`,
	"authorization.yaml": `apiVersion: auth.nvke.nvidia.com/v1alpha1
kind: AuthorizationConfiguration
operatorTenant: nca-op
issuers:
  idp:
    tenant: {claim: org}
    claims:
      - {name: groups, value: readers, grants: [reader]}
      - {name: groups, value: writers, grants: [writer]}
  ops:
    tenant: {fixed: nca-op}
    operators: true
    claims:
      - {name: groups, value: ops, grants: [writer]}
`,
}

// newClient loads testBundle and returns the client that asks it.
func newClient(t *testing.T) *authzlib.Client {
	t.Helper()
	dir := t.TempDir()
	for name, content := range testBundle {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600))
	}
	lb, err := authz.NewLocalBundle(dir, []string{"idp", "ops"})
	require.NoError(t, err)
	client, err := authzlib.NewClient(lb)
	require.NoError(t, err)
	return client
}

// principal is a caller from issuer with the given org claim, if any, and groups.
func principal(issuer, org string, groups ...string) *authn.Principal {
	claims := map[string]any{"groups": toAny(groups)}
	if org != "" {
		claims["org"] = org
	}
	return &authn.Principal{IssuerName: issuer, Subject: "subject-" + org, Claims: claims}
}

func toAny(values []string) []any {
	out := make([]any, len(values))
	for i, v := range values {
		out[i] = v
	}
	return out
}

var (
	reader   = principal("idp", "nca-a", "readers")
	writer   = principal("idp", "nca-a", "writers")
	noTenant = principal("idp", "", "writers")
	operator = principal("ops", "", "ops")
)

// fakeTenants looks tenants up in a map, or fails every lookup with err.
type fakeTenants struct {
	tenants map[uuid.UUID]string
	err     error
}

func (f fakeTenants) lookup(id uuid.UUID) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	tenant, ok := f.tenants[id]
	if !ok {
		return "", db.ErrNotFound
	}
	return tenant, nil
}

func (f fakeTenants) GetClusterTenant(_ context.Context, id uuid.UUID) (string, error) {
	return f.lookup(id)
}

func (f fakeTenants) GetNodePoolTenant(_ context.Context, id uuid.UUID) (string, error) {
	return f.lookup(id)
}

func (f fakeTenants) GetNodeSetTenant(_ context.Context, id uuid.UUID) (string, error) {
	return f.lookup(id)
}

func (f fakeTenants) GetNodeTenant(_ context.Context, id uuid.UUID) (string, error) {
	return f.lookup(id)
}

var (
	ownCluster    = uuid.New()
	otherCluster  = uuid.New()
	legacyCluster = uuid.New()
	ownNodePool   = uuid.New()
	ownNodeSet    = uuid.New()
	ownNode       = uuid.New()
	missing       = uuid.New()

	tenants = fakeTenants{tenants: map[uuid.UUID]string{
		ownCluster:    "nca-a",
		otherCluster:  "nca-b",
		legacyCluster: "",
		ownNodePool:   "nca-a",
		ownNodeSet:    "nca-a",
		ownNode:       "nca-a",
	}}
)

// outcomes records what the middleware counted.
type outcomes struct {
	mu   sync.Mutex
	seen []string
}

func (o *outcomes) record(outcome, _ string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seen = append(o.seen, outcome)
}

// result is what one request through the middleware produced.
type result struct {
	status  int
	body    string
	reached bool
	caller  authzlib.Caller
	listFor *string
	counted []string
}

// serve sends request for operationID through a new Middleware, as p. A request
// that reaches the handler reports status 200.
func serve(t *testing.T, client *authzlib.Client, lookups db.TenantQueries, p *authn.Principal, operationID string, request any) result {
	t.Helper()
	var counted outcomes
	logger := slog.New(slog.DiscardHandler)
	m := authz.NewMiddleware(client, lookups, counted.record, logger)

	var got result
	next := func(ctx context.Context, w http.ResponseWriter, _ *http.Request, _ any) (any, error) {
		got.reached = true
		got.caller, _ = authz.CallerFromContext(ctx)
		got.listFor = authz.ListTenant(ctx)
		w.WriteHeader(http.StatusOK)
		return "handled", nil
	}
	ctx := context.Background()
	if p != nil {
		ctx = authn.ContextWithPrincipal(ctx, p)
	}
	rec := httptest.NewRecorder()
	response, err := m.Strict(next, operationID)(ctx, rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/api", http.NoBody), request)
	require.NoError(t, err)
	if got.reached {
		assert.Equal(t, "handled", response)
	} else {
		assert.Nil(t, response, "a refusal writes its own response and returns none")
	}
	got.status, got.body, got.counted = rec.Code, rec.Body.String(), counted.seen
	return got
}

const notAuthorizedBody = `{"message":"Not authorized"}` + "\n"

func TestMiddleware(t *testing.T) {
	t.Parallel()
	client := newClient(t)

	getCluster := func(id uuid.UUID) api.GetClusterRequestObject { return api.GetClusterRequestObject{ClusterID: id} }
	createNodePool := func(id uuid.UUID) api.CreateNodePoolRequestObject {
		return api.CreateNodePoolRequestObject{Body: &api.CreateNodePoolJSONRequestBody{ClusterID: id}}
	}
	tests := []struct {
		name        string
		principal   *authn.Principal
		operationID string
		request     any
		wantStatus  int
		wantBody    string
		wantOutcome string
		wantCaller  authzlib.Caller
	}{
		{
			name: "no principal", principal: nil, operationID: "GetCluster", request: getCluster(ownCluster),
			wantStatus: http.StatusForbidden, wantBody: notAuthorizedBody, wantOutcome: authz.OutcomeError,
		},
		{
			name: "a reader gets its own cluster", principal: reader, operationID: "GetCluster", request: getCluster(ownCluster),
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "a reader deletes its own cluster", principal: reader, operationID: "DeleteCluster",
			request:    api.DeleteClusterRequestObject{ClusterID: ownCluster},
			wantStatus: http.StatusForbidden, wantBody: notAuthorizedBody, wantOutcome: "deny",
		},
		{
			name: "a reader gets another tenant's cluster", principal: reader, operationID: "GetCluster", request: getCluster(otherCluster),
			wantStatus: http.StatusNotFound, wantOutcome: "not_found",
		},
		{
			name: "a reader gets a missing cluster", principal: reader, operationID: "GetCluster", request: getCluster(missing),
			wantStatus: http.StatusNotFound, wantOutcome: "not_found",
		},
		{
			name: "a reader gets a cluster no tenant owns", principal: reader, operationID: "GetCluster", request: getCluster(legacyCluster),
			wantStatus: http.StatusNotFound, wantOutcome: "not_found",
		},
		{
			name: "a reader gets its own node pool", principal: reader, operationID: "GetNodePool",
			request:    api.GetNodePoolRequestObject{NodePoolID: ownNodePool},
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "a reader gets its own node set", principal: reader, operationID: "GetNodeSet",
			request:    api.GetNodeSetRequestObject{NodeSetID: ownNodeSet},
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "a reader gets its own node", principal: reader, operationID: "GetNode",
			request:    api.GetNodeRequestObject{NodeID: ownNode},
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "a writer creates a node pool on its own cluster", principal: writer, operationID: "CreateNodePool",
			request:    createNodePool(ownCluster),
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "a writer creates a node pool on another tenant's cluster", principal: writer, operationID: "CreateNodePool",
			request:    createNodePool(otherCluster),
			wantStatus: http.StatusNotFound, wantOutcome: "not_found",
		},
		{
			name: "a writer creates a node pool on a missing cluster", principal: writer, operationID: "CreateNodePool",
			request:    createNodePool(missing),
			wantStatus: http.StatusNotFound, wantOutcome: "not_found",
		},
		{
			name: "a caller with no tenant gets a cluster", principal: noTenant, operationID: "GetCluster", request: getCluster(ownCluster),
			wantStatus: http.StatusForbidden, wantBody: notAuthorizedBody, wantOutcome: "no_tenant",
		},
		{
			name: "a caller with no tenant lists releases", principal: noTenant, operationID: "ListReleases",
			request:    api.ListReleasesRequestObject{},
			wantStatus: http.StatusOK, wantOutcome: "allow",
		},
		{
			name: "a caller with no tenant lists clusters", principal: noTenant, operationID: "ListClusters",
			request:    api.ListClustersRequestObject{},
			wantStatus: http.StatusForbidden, wantBody: notAuthorizedBody, wantOutcome: "no_tenant",
		},
		{
			name: "a reader lists clusters", principal: reader, operationID: "ListClusters",
			request:    api.ListClustersRequestObject{},
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-a"},
		},
		{
			name: "an operator gets another tenant's cluster", principal: operator, operationID: "GetCluster", request: getCluster(otherCluster),
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-op", Operator: true},
		},
		{
			name: "an operator gets a cluster no tenant owns", principal: operator, operationID: "GetCluster", request: getCluster(legacyCluster),
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-op", Operator: true},
		},
		{
			name: "an operator gets a missing cluster", principal: operator, operationID: "GetCluster", request: getCluster(missing),
			wantStatus: http.StatusNotFound, wantOutcome: "allow",
		},
		{
			name: "an operator lists clusters", principal: operator, operationID: "ListClusters",
			request:    api.ListClustersRequestObject{},
			wantStatus: http.StatusOK, wantOutcome: "allow", wantCaller: authzlib.Caller{Tenant: "nca-op", Operator: true},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := serve(t, client, tenants, tt.principal, tt.operationID, tt.request)
			assert.Equal(t, tt.wantStatus, got.status)
			assert.Equal(t, tt.wantBody, got.body)
			assert.Equal(t, []string{tt.wantOutcome}, got.counted)
			assert.Equal(t, tt.wantStatus == http.StatusOK, got.reached)
			assert.Equal(t, tt.wantCaller, got.caller)
			if got.reached && !tt.wantCaller.Operator {
				assert.Equal(t, &tt.wantCaller.Tenant, got.listFor, "a list is filtered to the caller's tenant")
			} else {
				assert.Nil(t, got.listFor, "an operator's list is not filtered")
			}
		})
	}
}

// A missing object answers exactly like another tenant's, for every caller
// who isn't an operator, so an ID reveals nothing.
func TestAMissingObjectAnswersLikeAnotherTenants(t *testing.T) {
	t.Parallel()
	client := newClient(t)

	for name, p := range map[string]*authn.Principal{"reader": reader, "writer": writer, "no tenant": noTenant} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			for _, operationID := range []string{"GetCluster", "DeleteCluster"} {
				var other, absent any = api.GetClusterRequestObject{ClusterID: otherCluster}, api.GetClusterRequestObject{ClusterID: missing}
				if operationID == "DeleteCluster" {
					other, absent = api.DeleteClusterRequestObject{ClusterID: otherCluster}, api.DeleteClusterRequestObject{ClusterID: missing}
				}
				want := serve(t, client, tenants, p, operationID, other)
				got := serve(t, client, tenants, p, operationID, absent)
				assert.Equal(t, want.status, got.status, operationID)
				assert.Equal(t, want.body, got.body, operationID)
				assert.Equal(t, want.counted, got.counted, operationID)
			}
		})
	}
}

// A failed lookup answers a generic 500, and the error stays in the log.
func TestALookupErrorIsAGeneric500(t *testing.T) {
	t.Parallel()

	failing := fakeTenants{err: errors.New("dial tcp db.internal.example:5432: connection refused")}
	got := serve(t, newClient(t), failing, reader, "GetCluster", api.GetClusterRequestObject{ClusterID: ownCluster})
	assert.Equal(t, http.StatusInternalServerError, got.status)
	assert.JSONEq(t, `{"message":"Internal Server Error"}`, got.body)
	assert.False(t, got.reached)
	assert.Equal(t, []string{authz.OutcomeError}, got.counted)
}

// Through the generated strict handler, a refusal is the whole response: the
// handler writes nothing after the middleware returns (nil, nil).
func TestTheGeneratedHandlerWritesNothingAfterARefusal(t *testing.T) {
	t.Parallel()

	logger := slog.New(slog.DiscardHandler)
	m := authz.NewMiddleware(newClient(t), tenants, nil, logger)
	failOnError := func(_ http.ResponseWriter, _ *http.Request, err error) {
		t.Errorf("the generated handler reported %v", err)
	}
	// No handler is implemented: every request here is refused before one runs.
	handler := api.NewStrictHandlerWithOptions(struct{ api.StrictServerInterface }{}, []api.StrictMiddlewareFunc{m.Strict},
		api.StrictHTTPServerOptions{RequestErrorHandlerFunc: failOnError, ResponseErrorHandlerFunc: failOnError})

	tests := []struct {
		name       string
		serve      func(w http.ResponseWriter, r *http.Request)
		wantStatus int
		wantBody   string
	}{
		{
			name:       "not found",
			serve:      func(w http.ResponseWriter, r *http.Request) { handler.GetCluster(w, r, otherCluster) },
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "denied",
			serve:      func(w http.ResponseWriter, r *http.Request) { handler.DeleteCluster(w, r, ownCluster) },
			wantStatus: http.StatusForbidden,
			wantBody:   notAuthorizedBody,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			rec := httptest.NewRecorder()
			ctx := authn.ContextWithPrincipal(t.Context(), reader)
			tt.serve(rec, httptest.NewRequestWithContext(ctx, http.MethodGet, "/api/clusters", http.NoBody))
			assert.Equal(t, tt.wantStatus, rec.Code)
			assert.Equal(t, tt.wantBody, rec.Body.String())
		})
	}
}

func TestNewLocalBundleRefusesAMissingDirectory(t *testing.T) {
	t.Parallel()

	_, err := authz.NewLocalBundle(filepath.Join(t.TempDir(), "missing"), []string{"idp"})
	require.ErrorContains(t, err, "load the authorization bundle")
}
