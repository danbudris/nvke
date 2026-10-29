// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authz authorizes API requests with the auth/authz client and the
// LocalBundle backend. Middleware asks about each request after authentication
// and request validation, and puts the authorized caller on the context, where
// handlers read it to record a new cluster's tenant and to filter lists.
package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	authzlib "github.com/dsx-ai-factory/nvke/auth/authz"
	"github.com/dsx-ai-factory/nvke/auth/authz/localbundle"

	"github.com/dsx-ai-factory/nvke/controller/api"
)

// The reload results ReloadRecorder counts.
const (
	ReloadUnchanged = "unchanged"
	ReloadReloaded  = "reloaded"
	ReloadFailed    = "failed"
)

// ReloadRecorder counts one bundle reload by its result.
type ReloadRecorder func(result string)

// Reloader is a backend that reloads its policy, such as a LocalBundle.
type Reloader interface {
	Reload() (changed bool, err error)
}

// Actions returns every operationId in the API spec, sorted. These are the
// actions the middleware asks about. It reads api.OpenapiYAML, because the
// spec api.GetSwagger returns has the operationIds renamed to Go names.
func Actions() ([]string, error) {
	swagger, err := openapi3.NewLoader().LoadFromData([]byte(api.OpenapiYAML))
	if err != nil {
		return nil, fmt.Errorf("load the OpenAPI spec: %w", err)
	}
	var actions []string
	for _, item := range swagger.Paths.Map() {
		for _, op := range item.Operations() {
			actions = append(actions, op.OperationID)
		}
	}
	slices.Sort(actions)
	return actions, nil
}

// NewLocalBundle loads the bundle in dir for the API's actions and resource
// types. issuers are the issuer names in the authN config.
func NewLocalBundle(dir string, issuers []string) (*localbundle.LocalBundle, error) {
	actions, err := Actions()
	if err != nil {
		return nil, err
	}
	lb, err := localbundle.New(localbundle.Options{
		Dir:           dir,
		Issuers:       issuers,
		Actions:       actions,
		ResourceTypes: resourceTypes,
	})
	if err != nil {
		return nil, fmt.Errorf("load the authorization bundle in %s: %w", dir, err)
	}
	return lb, nil
}

// RunReloads reloads backend every interval until ctx is done. A failed
// reload keeps the live bundle.
func RunReloads(ctx context.Context, backend Reloader, interval time.Duration, record ReloadRecorder, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changed, err := backend.Reload()
		switch {
		case err != nil:
			record(ReloadFailed)
			logger.Error("Failed to reload the authorization bundle; keeping the live one", "error", err)
		case changed:
			record(ReloadReloaded)
			logger.Info("Reloaded the authorization bundle")
		default:
			record(ReloadUnchanged)
		}
	}
}

// callerKey is unexported so no other package can collide with it.
type callerKey struct{}

// ContextWithCaller returns a copy of ctx that carries the authorized caller.
func ContextWithCaller(ctx context.Context, c authzlib.Caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

// CallerFromContext returns the caller the middleware authorized. False when
// authorization is off.
func CallerFromContext(ctx context.Context) (authzlib.Caller, bool) {
	c, ok := ctx.Value(callerKey{}).(authzlib.Caller)
	return c, ok
}

// ListTenant returns the tenant a list must be filtered to: the caller's,
// unless the caller is an operator. Nil means no filter.
func ListTenant(ctx context.Context) *string {
	c, ok := CallerFromContext(ctx)
	if !ok || c.Operator {
		return nil
	}
	return &c.Tenant
}

// ErrNoCaller reports a request that reached a handler with authorization on
// but no authorized caller on its context.
var ErrNoCaller = errors.New("authorization is on, but the request has no authorized caller")
