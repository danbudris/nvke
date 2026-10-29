// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authz authorizes API requests with the auth/authz Guard and the
// LocalBundle backend. Middleware resolves each request's target after
// authentication and request validation and asks the Guard, which puts the
// authorized caller on the context, where handlers read it with
// auth/authz CallerFromContext and ListTenant.
package authz

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

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
