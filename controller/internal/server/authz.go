// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"

	authzlib "github.com/dsx-ai-factory/nvke/auth/authz"
)

// listTenant returns the tenant a list is filtered to. With authorization off
// it is nil, no filter. With it on, it is authzlib.ListTenant, which fails
// closed on a context with no authorized caller.
func listTenant(ctx context.Context, authzEnabled bool) (*string, error) {
	if !authzEnabled {
		return nil, nil //nolint:nilnil // nil is "no filter"
	}
	return authzlib.ListTenant(ctx) //nolint:wrapcheck // ErrNoCaller answers a generic 500
}
