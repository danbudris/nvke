// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"

	"github.com/dsx-ai-factory/nvke/auth/authn"
)

const (
	// OutcomeError is the outcome a Recorder counts for a request refused
	// because it couldn't be decided: no authenticated principal, or the
	// client failing closed. Only a Recorder counts it. It is never a backend
	// Decision's outcome: Client.Authorize fails closed on it.
	OutcomeError Outcome = "error"

	// missingID stands in for a missing object's ID when Query.Validate would
	// refuse that ID. It is a valid ID, so a malformed ID answers like a
	// well-formed one. See Guard.Check.
	missingID = "missing"
)

// Recorder counts one Guard decision by outcome and action. A function rather
// than a Prometheus counter, so this package has no metrics dependency.
type Recorder func(outcome Outcome, action string)

// Target is what one request acts on, as the API resolves it from the request.
// Action becomes a metric label, so it must come from the API's fixed set of
// actions, never from the request itself.
//
// Every existing object must have an owner tenant and an ID that
// Query.Validate accepts. An API with objects that have no owner must give
// them one, such as by a backfill: a ScopeObject Resource with no Tenant
// fails closed for every caller.
type Target struct {
	Action   string
	Resource Resource

	// Missing reports that the object the request names doesn't exist.
	// Resource.Type and Resource.ID name it. Check ignores Resource.Scope and
	// Resource.Tenant. See Guard.Check.
	Missing bool
}

// Guard puts a Client in front of an API. It reads the authenticated caller,
// asks the client, counts every decision and logs every refusal, and puts the
// authorized caller on the context. It holds nothing about any transport.
// Immutable after construction and safe for concurrent use.
type Guard struct {
	client *Client
	logger *slog.Logger
	record Recorder

	// missingTenant owns every missing object. It is random, so no caller
	// holds it. See Check.
	missingTenant string
}

// NewGuard returns a Guard that asks client. logger and record may be nil.
func NewGuard(client *Client, logger *slog.Logger, record Recorder) (*Guard, error) {
	if client == nil {
		return nil, errors.New("guard requires a client")
	}
	if logger == nil {
		logger = slog.Default()
	}
	if record == nil {
		record = func(Outcome, string) {}
	}
	return &Guard{
		client:        client,
		logger:        logger,
		record:        record,
		missingTenant: "missing-" + rand.Text(),
	}, nil
}

// Check authorizes t for the Principal that auth/authn put on ctx. On an allow
// it returns ctx carrying the authorized Caller, and a nil error. Otherwise it
// returns ctx unchanged and an error for the API to answer with:
//
//   - ErrNotFound, ErrDenied or ErrNoTenant, bare, for a refusal.
//   - An error wrapping ErrDenied when it fails closed: ctx carries no
//     Principal, or Client.Authorize failed closed. It counts OutcomeError.
//
// A request with no Principal answers ErrDenied, so authZ requires auth/authn
// in enforcing mode on every route it guards. Permissive authN serves a
// request it would reject with no Principal, and Check refuses it: permissive
// authN doesn't make authZ permissive. A nil Guard refuses the same way and
// counts nothing.
//
// A missing object (Target.Missing) answers like another tenant's object for
// every caller who isn't an operator, so an ID reveals nothing about objects
// the caller can't reach. Check asks about it as a ScopeObject with the
// requested ID, owned by a random tenant that exists only in this Guard, so no
// caller holds it. Policy sees the same resource whether or not another
// tenant's object has that ID. An ID that Query.Validate would refuse becomes
// missingID, so a malformed ID answers like a well-formed one. No existing
// object has such an ID (see Target), so there is no answer to match. The
// backend refuses the caller as it would for another tenant's object, and
// Check answers that refusal unchanged.
//
// An operator's request goes on to policy, as for another tenant's object.
// Where policy allows, Check answers a missing object with ErrNotFound and
// counts OutcomeNotFound, and allows another tenant's object. A backend
// can't decide an operator's request by the object's tenant (see
// Authorizer.Authorize), so an operator learns an object is missing only where
// policy lets it reach the object.
func (g *Guard) Check(ctx context.Context, t Target) (context.Context, error) {
	if g == nil || g.client == nil {
		return ctx, fmt.Errorf("%w: guard has no client", ErrDenied)
	}
	principal, ok := authn.PrincipalFromContext(ctx)
	if !ok {
		err := fmt.Errorf("%w: no authenticated principal", ErrDenied)
		g.record(OutcomeError, t.Action)
		g.logger.ErrorContext(ctx, "failed to authorize request", "action", t.Action, "error", err)
		return ctx, err
	}

	resource := t.Resource
	if t.Missing {
		id := t.Resource.ID
		if checkString(id, maxNameBytes) != nil {
			id = missingID
		}
		resource = Resource{Type: t.Resource.Type, ID: id, Scope: ScopeObject, Tenant: g.missingTenant}
	}
	d, err := g.client.Authorize(ctx, Query{Principal: *principal, Action: t.Action, Resource: resource})
	outcome := d.Outcome
	switch {
	case failedClosed(err):
		outcome = OutcomeError
	case err == nil && t.Missing:
		outcome, err = OutcomeNotFound, ErrNotFound
	}
	g.record(outcome, t.Action)
	if err == nil {
		return ContextWithCaller(ctx, d.Caller), nil
	}

	level, message := slog.LevelInfo, "refused request"
	if outcome == OutcomeError {
		level, message = slog.LevelError, "failed to authorize request"
	}
	// The resource's tenant stays out of the log: for a missing object it is
	// the random tenant, which must stay unknown. A caller holding it would
	// pass the isolation check on a missing object, so where policy denies the
	// action it would be refused as denied rather than not found.
	g.logger.Log(ctx, level, message,
		"action", t.Action,
		"outcome", string(outcome),
		"missing", t.Missing,
		"issuer", principal.IssuerName,
		"tenant", d.Caller.Tenant,
		"reasons", d.Reasons,
		"error", err,
	)
	return ctx, err
}

// failedClosed reports whether err is Client.Authorize failing closed rather
// than a refusal. A refusal is a bare sentinel; a failure wraps ErrDenied.
func failedClosed(err error) bool {
	switch err {
	case nil, ErrDenied, ErrNotFound, ErrNoTenant: //nolint:errorlint // only the bare sentinel is a refusal
		return false
	default:
		return true
	}
}
