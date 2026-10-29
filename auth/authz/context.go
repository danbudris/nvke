// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"errors"
	"fmt"
)

// ErrNoCaller reports a request that reached code needing an authorized
// caller with a valid tenant, and has none on its context. It is a wiring
// fault in the API, not a refusal, so an API answers it with 500.
var ErrNoCaller = errors.New("request has no authorized caller with a valid tenant")

// callerContextKey is unexported so no other package can collide with it.
type callerContextKey struct{}

// ContextWithCaller returns a copy of ctx that carries c as the authorized
// caller. Guard.Check calls it on an allow. Other code calls it only in tests,
// and in adapters that carry a Guard's caller onto another context.
func ContextWithCaller(ctx context.Context, c Caller) context.Context {
	return context.WithValue(ctx, callerContextKey{}, c)
}

// CallerFromContext returns the authorized caller ctx carries. False when ctx
// carries none.
func CallerFromContext(ctx context.Context) (Caller, bool) {
	c, ok := ctx.Value(callerContextKey{}).(Caller)
	return c, ok
}

// ListTenant returns the tenant a list must be filtered to: the caller's, or
// nil for an operator, whose list is not filtered. It fails closed, with an
// error, when ctx carries no authorized caller or the caller has no valid
// tenant, such as a caller with no tenant allowed on a ScopeGlobal resource.
func ListTenant(ctx context.Context) (*string, error) {
	c, ok := CallerFromContext(ctx)
	if !ok {
		return nil, ErrNoCaller
	}
	if err := CheckTenantID(c.Tenant); err != nil {
		return nil, fmt.Errorf("%w: caller tenant %w", ErrNoCaller, err)
	}
	if c.Operator {
		return nil, nil //nolint:nilnil // nil is the documented "no filter" for an operator
	}
	return &c.Tenant, nil
}
