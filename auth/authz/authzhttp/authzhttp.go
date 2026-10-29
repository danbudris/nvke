// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package authzhttp answers an authz error over net/http: its status and
// body. An API calls authz.Guard.Check and answers an error with WriteError.
//
// Route resolution stays in each API: which action a request is, and which
// resource it targets, including any lookup of the owning tenant.
package authzhttp

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/dsx-ai-factory/nvke/auth/authz"
	"github.com/dsx-ai-factory/nvke/auth/internal/httperror"
)

const (
	// forbiddenMessage is the body of every 403. It names no reason, so a
	// caller learns nothing about the policy or its own tenancy.
	forbiddenMessage = "Not authorized"
)

// statusFor returns the HTTP status that answers err: 404 for
// authz.ErrNotFound, 403 for authz.ErrDenied or authz.ErrNoTenant, wrapped or
// bare, and 500 for anything else. Failing closed wraps authz.ErrDenied, so it
// answers 403, as authz.Client.Authorize documents. A nil error answers 500,
// never a success.
func statusFor(err error) int {
	switch {
	case errors.Is(err, authz.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, authz.ErrDenied), errors.Is(err, authz.ErrNoTenant):
		return http.StatusForbidden
	default:
		return http.StatusInternalServerError
	}
}

// WriteError answers r with err's status and a fixed body that never holds
// err's text. A 404 has no body, like every 404 in the NVKE API. A 403 or a
// 500 has the API's error body, {"message": ...}. A 500 logs err to logger,
// which may be nil. authz.Guard.Check has already logged a refusal.
func WriteError(w http.ResponseWriter, r *http.Request, err error, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	status := statusFor(err)
	var message string
	switch status {
	case http.StatusForbidden:
		message = forbiddenMessage
	case http.StatusInternalServerError:
		logger.ErrorContext(r.Context(), "failed to authorize request", "error", err)
		message = http.StatusText(status)
	}
	httperror.Write(w, r, status, message, logger)
}
