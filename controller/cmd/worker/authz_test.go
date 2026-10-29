// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/auth/authn"

	"github.com/dsx-ai-factory/nvke/controller/internal/config"
)

// Authorization that can't start fails startup rather than serving without it.
func TestSetupAuthorizationRefusesToStart(t *testing.T) {
	t.Parallel()

	apiAuth := &authn.Config{Issuers: []authn.Issuer{{Name: "idp"}}}
	tests := []struct {
		name    string
		dir     string
		apiAuth *authn.Config
		mode    string
		wantErr string
	}{
		{name: "authentication off", dir: t.TempDir(), mode: "off", wantErr: "authorization needs it enforcing"},
		{name: "authentication permissive", dir: t.TempDir(), apiAuth: apiAuth, mode: "permissive", wantErr: "authorization needs it enforcing"},
		{
			name: "a missing bundle directory", dir: filepath.Join(t.TempDir(), "missing"), apiAuth: apiAuth, mode: "enforcing",
			wantErr: "load the authorization bundle",
		},
		{name: "an empty bundle directory", dir: t.TempDir(), apiAuth: apiAuth, mode: "enforcing", wantErr: "read policies.cedar"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			cfg := config.Config{AuthzBundleDir: tt.dir}
			_, err := setupAuthorization(t.Context(), cfg, tt.apiAuth, tt.mode, slog.New(slog.DiscardHandler))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

func TestSetupAuthorizationIsOffWithoutABundle(t *testing.T) {
	t.Parallel()

	client, err := setupAuthorization(t.Context(), config.Config{}, nil, "off", slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	require.Nil(t, client)
}
