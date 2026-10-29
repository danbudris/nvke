// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/dsx-ai-factory/nvke/auth/authn"
	authzlib "github.com/dsx-ai-factory/nvke/auth/authz"

	"github.com/dsx-ai-factory/nvke/controller/api"
	"github.com/dsx-ai-factory/nvke/controller/internal/db"
)

const (
	// The resource types the middleware asks about.
	typeCluster    = "Cluster"
	typeNodePool   = "NodePool"
	typeNodeSet    = "NodeSet"
	typeNode       = "Node"
	typeCollection = "Collection"

	// OutcomeError is the outcome RequestRecorder counts when the request was
	// refused because it couldn't be decided: no principal, a failed lookup,
	// or the client failing closed.
	OutcomeError = "error"

	// notAuthorized is the body of every 403 this middleware writes. It
	// names no reason, so a caller learns nothing about the policy.
	notAuthorized = "Not authorized"
)

// RequestRecorder counts one decision by outcome and action.
type RequestRecorder func(outcome, action string)

// Middleware authorizes each API request. It is safe for concurrent use.
type Middleware struct {
	client  *authzlib.Client
	tenants db.TenantQueries
	record  RequestRecorder
	logger  *slog.Logger

	// unowned is the tenant of an object no tenant owns: a missing object, or
	// a cluster created while authorization was off. It is a random ID no
	// caller holds, so only an operator reaches such an object, and anyone
	// else is refused exactly as for another tenant's object.
	unowned string
}

// NewMiddleware returns a Middleware that asks client. record may be nil.
func NewMiddleware(client *authzlib.Client, tenants db.TenantQueries, record RequestRecorder, logger *slog.Logger) *Middleware {
	if record == nil {
		record = func(string, string) {}
	}
	return &Middleware{client: client, tenants: tenants, record: record, logger: logger, unowned: uuid.NewString()}
}

// Strict is an api.StrictMiddlewareFunc. The generated handler calls it after
// decoding the request, so request validation answers 400 first. On allow it
// puts the caller on the context and calls next. Otherwise it writes the
// response and returns (nil, nil), on which the generated handler writes
// nothing more.
func (m *Middleware) Strict(next api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	action := strings.ToLower(operationID[:1]) + operationID[1:]
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		caller, status := m.authorize(ctx, action, request)
		if status != http.StatusOK {
			m.writeRefusal(w, status)
			return nil, nil
		}
		return next(ContextWithCaller(ctx, caller), w, r, request)
	}
}

// authorize returns the caller on allow, with http.StatusOK, or the status to
// refuse with. A missing object answers 404 even on allow, so an operator
// sees what a handler would have answered.
func (m *Middleware) authorize(ctx context.Context, action string, request any) (authzlib.Caller, int) {
	principal, ok := authn.PrincipalFromContext(ctx)
	if !ok {
		m.record(OutcomeError, action)
		m.logger.ErrorContext(ctx, "Refused a request with no authenticated principal", "action", action)
		return authzlib.Caller{}, http.StatusForbidden
	}
	resource, missing, err := m.resource(ctx, action, request)
	if err != nil {
		m.record(OutcomeError, action)
		m.logger.ErrorContext(ctx, "Failed to find the resource to authorize", "action", action, "error", err)
		return authzlib.Caller{}, http.StatusInternalServerError
	}

	d, err := m.client.Authorize(ctx, authzlib.Query{Principal: *principal, Action: action, Resource: resource})
	outcome := string(d.Outcome)
	if failed(err) {
		outcome = OutcomeError
	}
	m.record(outcome, action)

	status := http.StatusForbidden
	switch {
	case err == nil && !missing:
		return d.Caller, http.StatusOK
	case err == nil, errors.Is(err, authzlib.ErrNotFound):
		status = http.StatusNotFound
	}
	m.logger.DebugContext(ctx, "Refused a request",
		"action", action,
		"outcome", outcome,
		"status", status,
		"issuer", principal.IssuerName,
		"tenant", d.Caller.Tenant,
		"reasons", d.Reasons,
		"error", err,
	)
	return d.Caller, status
}

// failed reports whether err is the client failing closed rather than a
// refusal. A refusal is a bare sentinel; a failure wraps ErrDenied.
func failed(err error) bool {
	switch err {
	case nil, authzlib.ErrDenied, authzlib.ErrNotFound, authzlib.ErrNoTenant: //nolint:errorlint // only the bare sentinel is a refusal
		return false
	default:
		return true
	}
}

// resource returns the resource action acts on, and whether it is an object
// that doesn't exist.
func (m *Middleware) resource(ctx context.Context, action string, request any) (authzlib.Resource, bool, error) {
	if c, ok := collections[action]; ok {
		return authzlib.Resource{Type: typeCollection, ID: c.id, Scope: c.scope}, false, nil
	}
	o, ok := objects[action]
	if !ok {
		return authzlib.Resource{}, false, fmt.Errorf("action %s has no resource mapping", action)
	}
	id, ok := o.id(request)
	if !ok {
		return authzlib.Resource{}, false, fmt.Errorf("action %s has a request of type %T", action, request)
	}
	tenant, err := o.tenant(m.tenants, ctx, id)
	missing := errors.Is(err, db.ErrNotFound)
	if err != nil && !missing {
		return authzlib.Resource{}, false, fmt.Errorf("look up the tenant of %s %s: %w", o.typ, id, err)
	}
	if tenant == "" {
		tenant = m.unowned
	}
	return authzlib.Resource{Type: o.typ, ID: id.String(), Scope: authzlib.ScopeObject, Tenant: tenant}, missing, nil
}

// writeRefusal writes the response to a request the middleware stopped. A 404
// has no body, like every 404 the API returns.
func (m *Middleware) writeRefusal(w http.ResponseWriter, status int) {
	if status == http.StatusNotFound {
		w.WriteHeader(status)
		return
	}
	message := notAuthorized
	if status == http.StatusInternalServerError {
		message = http.StatusText(status)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(api.GenericError{Message: message}); err != nil {
		m.logger.Error("Failed to write the authorization response", "error", err)
	}
}

// collection is the resource of a list, create or global action.
type collection struct {
	id    string
	scope authzlib.Scope
}

//nolint:gochecknoglobals // fixed for the life of the process
var (
	resourceTypes = []string{typeCluster, typeNodePool, typeNodeSet, typeNode, typeCollection}

	collections = map[string]collection{
		"listClusters":       {id: "clusters", scope: authzlib.ScopeList},
		"listNodePools":      {id: "nodePools", scope: authzlib.ScopeList},
		"listNodeSets":       {id: "nodeSets", scope: authzlib.ScopeList},
		"listNodes":          {id: "nodes", scope: authzlib.ScopeList},
		"listReleases":       {id: "releases", scope: authzlib.ScopeGlobal},
		"listConfigProfiles": {id: "configProfiles", scope: authzlib.ScopeGlobal},
		"createCluster":      {id: "clusters", scope: authzlib.ScopeCreate},
	}

	objects = map[string]object{
		"getCluster":                          cluster(func(r api.GetClusterRequestObject) uuid.UUID { return r.ClusterID }),
		"updateCluster":                       cluster(func(r api.UpdateClusterRequestObject) uuid.UUID { return r.ClusterID }),
		"deleteCluster":                       cluster(func(r api.DeleteClusterRequestObject) uuid.UUID { return r.ClusterID }),
		"getClusterControlPlane":              cluster(func(r api.GetClusterControlPlaneRequestObject) uuid.UUID { return r.ClusterID }),
		"getClusterControlPlaneConfigHistory": cluster(func(r api.GetClusterControlPlaneConfigHistoryRequestObject) uuid.UUID { return r.ClusterID }),
		"getClusterSpireServer":               cluster(func(r api.GetClusterSpireServerRequestObject) uuid.UUID { return r.ClusterID }),
		"updateClusterSpireServer":            cluster(func(r api.UpdateClusterSpireServerRequestObject) uuid.UUID { return r.ClusterID }),
		// A new node pool is authorized as an action on its cluster.
		"createNodePool": cluster(func(r api.CreateNodePoolRequestObject) uuid.UUID {
			if r.Body == nil {
				return uuid.Nil
			}
			return r.Body.ClusterID
		}),
		"getNodePool":    nodePool(func(r api.GetNodePoolRequestObject) uuid.UUID { return r.NodePoolID }),
		"updateNodePool": nodePool(func(r api.UpdateNodePoolRequestObject) uuid.UUID { return r.NodePoolID }),
		"deleteNodePool": nodePool(func(r api.DeleteNodePoolRequestObject) uuid.UUID { return r.NodePoolID }),
		"getNodeSet":     newObject(typeNodeSet, db.TenantQueries.GetNodeSetTenant, func(r api.GetNodeSetRequestObject) uuid.UUID { return r.NodeSetID }),
		"getNode":        newObject(typeNode, db.TenantQueries.GetNodeTenant, func(r api.GetNodeRequestObject) uuid.UUID { return r.NodeID }),
		"deleteNode":     newObject(typeNode, db.TenantQueries.GetNodeTenant, func(r api.DeleteNodeRequestObject) uuid.UUID { return r.NodeID }),
	}
)

// object is the resource of an action on one object: its type, how to read
// its ID from the request, and how to look up its tenant.
type object struct {
	typ    string
	id     func(request any) (uuid.UUID, bool)
	tenant func(db.TenantQueries, context.Context, uuid.UUID) (string, error)
}

// newObject returns an object read from a request of type R.
func newObject[R any](typ string, tenant func(db.TenantQueries, context.Context, uuid.UUID) (string, error), id func(R) uuid.UUID) object {
	return object{typ: typ, tenant: tenant, id: func(request any) (uuid.UUID, bool) {
		r, ok := request.(R)
		if !ok {
			return uuid.Nil, false
		}
		return id(r), true
	}}
}

func cluster[R any](id func(R) uuid.UUID) object {
	return newObject(typeCluster, db.TenantQueries.GetClusterTenant, id)
}

func nodePool[R any](id func(R) uuid.UUID) object {
	return newObject(typeNodePool, db.TenantQueries.GetNodePoolTenant, id)
}
