// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//nolint:gochecknoglobals // Prometheus metrics are conventionally package-level globals
package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dsx-ai-factory/nvke/controller/internal/authz"
)

var (
	// action is an operationId, a closed set fixed by the API spec.
	authzRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nvke_authz_requests_total",
			Help: "Total API requests evaluated by authorization, by outcome and action. " +
				"outcome is allow, deny, not_found, no_tenant, or error for a request refused because it couldn't be decided.",
		},
		[]string{outcomeLabel, "action"},
	)

	authzReloadsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "nvke_authz_reloads_total",
			Help: "Total authorization bundle reloads, by result: unchanged, reloaded or failed. A failed reload keeps the live bundle.",
		},
		[]string{"result"},
	)

	_ authz.RequestRecorder = RecordAuthzRequest
	_ authz.ReloadRecorder  = RecordAuthzReload
)

func init() {
	prometheus.MustRegister(authzRequestsTotal, authzReloadsTotal)
}

// RecordAuthzRequest counts one authorization decision. Its signature is
// authz.RequestRecorder.
func RecordAuthzRequest(outcome, action string) {
	authzRequestsTotal.WithLabelValues(outcome, action).Inc()
}

// RecordAuthzReload counts one bundle reload. Its signature is
// authz.ReloadRecorder.
func RecordAuthzReload(result string) {
	authzReloadsTotal.WithLabelValues(result).Inc()
}
