// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/google/uuid"

	authzlib "github.com/dsx-ai-factory/nvke/auth/authz"
	"github.com/dsx-ai-factory/nvke/auth/authz/authzhttp"

	"github.com/dsx-ai-factory/nvke/controller/api"
	"github.com/dsx-ai-factory/nvke/controller/internal/db"
)

// The resource types the middleware asks about.
const (
	typeCluster    = "Cluster"
	typeNodePool   = "NodePool"
	typeNodeSet    = "NodeSet"
	typeNode       = "Node"
	typeCollection = "Collection"
)

// Middleware authorizes each API request: it resolves the request's target and
// asks an authzlib.Guard. It is safe for concurrent use.
type Middleware struct {
	guard   *authzlib.Guard
	tenants db.TenantQueries
	record  authzlib.Recorder
	logger  *slog.Logger
}

// NewMiddleware returns a Middleware that asks client. record counts every
// decision, and a failed tenant lookup as authzlib.OutcomeError; it may be nil.
func NewMiddleware(client *authzlib.Client, tenants db.TenantQueries, record authzlib.Recorder, logger *slog.Logger) (*Middleware, error) {
	if record == nil {
		record = func(authzlib.Outcome, string) {}
	}
	guard, err := authzlib.NewGuard(client, logger, record)
	if err != nil {
		return nil, err
	}
	return &Middleware{guard: guard, tenants: tenants, record: record, logger: logger}, nil
}

// Strict is an api.StrictMiddlewareFunc. The generated handler calls it after
// decoding the request, so request validation answers 400 first. On allow it
// calls next with the context the guard returns, which carries the caller.
// Otherwise it writes the response and returns (nil, nil), on which the
// generated handler writes nothing more.
func (m *Middleware) Strict(next api.StrictHandlerFunc, operationID string) api.StrictHandlerFunc {
	action := strings.ToLower(operationID[:1]) + operationID[1:]
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, request any) (any, error) {
		target, err := m.target(ctx, action, request)
		if err != nil {
			m.record(authzlib.OutcomeError, action)
			authzhttp.WriteError(w, r, err, m.logger)
			return nil, nil
		}
		ctx, err = m.guard.Check(ctx, target)
		if err != nil {
			authzhttp.WriteError(w, r, err, m.logger)
			return nil, nil
		}
		return next(ctx, w, r, request)
	}
}

// target returns what action acts on. An error is a failed lookup, never a
// refusal.
func (m *Middleware) target(ctx context.Context, action string, request any) (authzlib.Target, error) {
	if c, ok := collections[action]; ok {
		return authzlib.Target{Action: action, Resource: authzlib.Resource{Type: typeCollection, ID: c.id, Scope: c.scope}}, nil
	}
	o, ok := objects[action]
	if !ok {
		return authzlib.Target{}, fmt.Errorf("action %s has no resource mapping", action)
	}
	id, ok := o.id(request)
	if !ok {
		return authzlib.Target{}, fmt.Errorf("action %s has a request of type %T", action, request)
	}
	tenant, err := o.tenant(m.tenants, ctx, id)
	missing := errors.Is(err, db.ErrNotFound)
	if err != nil && !missing {
		return authzlib.Target{}, fmt.Errorf("look up the tenant of %s %s: %w", o.typ, id, err)
	}
	// A cluster created while authorization was off has no tenant. The guard
	// has no path for an unowned object, so it answers as a missing one: 404
	// for every caller, an operator included. A real deployment backfills an
	// owner for every such cluster before it turns authorization on.
	if tenant == "" {
		missing = true
	}
	return authzlib.Target{
		Action:   action,
		Resource: authzlib.Resource{Type: o.typ, ID: id.String(), Scope: authzlib.ScopeObject, Tenant: tenant},
		Missing:  missing,
	}, nil
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
