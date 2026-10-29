// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// Tenants, from controller/hack/authz-dev/bundle/authorization.yaml.
const (
	authzTenantA  = "nca-a"
	authzTenantA2 = "nca-a2"
	authzTenantB  = "nca-b"
)

// authzReloadTimeout bounds one bundle change reaching decisions: the
// kubelet's ConfigMap sync, then the controller's reload interval.
const authzReloadTimeout = 4 * time.Minute

// The LocalBundle authorization of the NVKE API, against the bundle and test
// IdP controller/Tiltfile deploys with NKE_AUTHZ_ENABLED=true. Ordered: the
// cases share two clusters, created by the first spec.
var _ = Describe("NVKE API authorization", Ordered, Label("authz"), func() {
	var (
		env *authzEnv

		readerA, writerA, writerA2, nobodyA, noOrg, impostor authzCaller
		readerB, writerB, operator, viewerOp                 authzCaller

		clusterA, clusterA2 string
	)

	BeforeAll(func(ctx SpecContext) {
		env = newAuthzEnv(ctx)

		readerA = env.idpCaller("reader-a", "idp-a", authzTenantA, "nvke-readers")
		writerA = env.idpCaller("writer-a", "idp-a", authzTenantA, "nvke-writers")
		writerA2 = env.idpCaller("writer-a2", "idp-a", authzTenantA2, "nvke-writers")
		nobodyA = env.idpCaller("nobody-a", "idp-a", authzTenantA, "nvke-nobody")
		noOrg = env.idpCaller("no-org", "idp-a", "", "nvke-writers")
		impostor = env.idpCaller("impostor", "idp-a", "nca-op", "nvke-writers")
		readerB = env.idpCaller("reader-b", "idp-b", "", "nvke-readers")
		writerB = env.idpCaller("writer-b", "idp-b", "", "nvke-writers")
		operator = env.saCaller("operator", "nke-client")
		viewerOp = env.saCaller("viewer-op", "nke-viewer")

		// Every cluster the specs create is deleted at the end; the deletes'
		// workflows are terminated like the creates'.
		DeferCleanup(func(ctx SpecContext) {
			for _, id := range []string{clusterA, clusterA2} {
				if id == "" {
					continue
				}
				r := env.do(ctx, operator, http.MethodDelete, "/clusters/"+id, nil)
				if r.status == http.StatusAccepted {
					env.terminateWorkflow(ctx, "teardown-cluster-"+id)
				}
			}
		})
	})

	It("1: creates a cluster in the creator's tenant", func(ctx SpecContext) {
		suffix := uuid.NewString()[:8]
		var r authzResponse
		r, clusterA = env.createCluster(ctx, writerA, "authz-a-"+suffix)
		expectStatus(r, http.StatusCreated, "writer-a creates cluster A")
		r, clusterA2 = env.createCluster(ctx, writerA2, "authz-a2-"+suffix)
		expectStatus(r, http.StatusCreated, "writer-a2 creates cluster A2")

		Expect(env.tenantOf(ctx, clusterA)).To(Equal(authzTenantA))
		Expect(env.tenantOf(ctx, clusterA2)).To(Equal(authzTenantA2))
	})

	It("2: lets a writer read, because writer includes reader", func(ctx SpecContext) {
		expectStatus(env.do(ctx, writerA, http.MethodGet, "/clusters/"+clusterA, nil), http.StatusOK, "writer-a gets A")
	})

	It("3: lets a reader get and list its tenant's clusters, and only those", func(ctx SpecContext) {
		expectStatus(env.do(ctx, readerA, http.MethodGet, "/clusters/"+clusterA, nil), http.StatusOK, "reader-a gets A")

		r := env.do(ctx, readerA, http.MethodGet, "/clusters", nil)
		expectStatus(r, http.StatusOK, "reader-a lists clusters")
		Expect(listIDs(r, "clusters")).To(Equal(env.tenantIDs(ctx, "clusters", authzTenantA)),
			"reader-a's list is exactly %s's clusters", authzTenantA)
	})

	It("4: refuses a reader's update and delete with 403", func(ctx SpecContext) {
		expectStatus(env.do(ctx, readerA, http.MethodPatch, "/clusters/"+clusterA, map[string]any{"enableCPNodeRecycling": false}),
			http.StatusForbidden, "reader-a updates A")
		expectStatus(env.do(ctx, readerA, http.MethodDelete, "/clusters/"+clusterA, nil),
			http.StatusForbidden, "reader-a deletes A")
	})

	It("5: hides another tenant's cluster with 404", func(ctx SpecContext) {
		expectStatus(env.do(ctx, writerA2, http.MethodGet, "/clusters/"+clusterA, nil), http.StatusNotFound, "writer-a2 gets A")
		expectStatus(env.do(ctx, writerA2, http.MethodDelete, "/clusters/"+clusterA, nil), http.StatusNotFound, "writer-a2 deletes A")
		expectStatus(env.do(ctx, writerA2, http.MethodPost, "/nodePools", env.nodePoolBody(clusterA)),
			http.StatusNotFound, "writer-a2 creates a node pool on A")
	})

	It("6: lists only the caller's tenant's clusters, node pools and nodes", func(ctx SpecContext) {
		for _, list := range []struct{ path, key, table string }{
			{"/clusters", "clusters", "clusters"},
			{"/nodePools", "nodePools", "node_pools"},
			{"/nodes", "nodes", "nodes"},
		} {
			r := env.do(ctx, writerA2, http.MethodGet, list.path, nil)
			expectStatus(r, http.StatusOK, "writer-a2 lists "+list.key)
			Expect(listIDs(r, list.key)).To(Equal(env.tenantIDs(ctx, list.table, authzTenantA2)),
				"writer-a2's %s are exactly %s's", list.key, authzTenantA2)
		}

		r := env.do(ctx, writerA2, http.MethodGet, "/nodePools?clusterID="+clusterA, nil)
		expectStatus(r, http.StatusOK, "writer-a2 lists A's node pools")
		Expect(listIDs(r, "nodePools")).To(BeEmpty(), "writer-a2 sees none of A's node pools")
	})

	It("7: answers a missing cluster ID as it answers another tenant's", func(ctx SpecContext) {
		missing := uuid.NewString()
		for _, tc := range []struct {
			caller authzCaller
			other  string // another tenant's existing cluster; "" for the operator
			want   int
		}{
			{writerA, clusterA2, http.StatusNotFound},
			{readerA, clusterA2, http.StatusNotFound},
			{noOrg, clusterA, http.StatusForbidden},
			{impostor, clusterA, http.StatusForbidden},
			{operator, "", http.StatusNotFound},
		} {
			r := env.do(ctx, tc.caller, http.MethodGet, "/clusters/"+missing, nil)
			expectStatus(r, tc.want, tc.caller.name+" gets a missing cluster")
			if tc.other == "" {
				continue
			}
			other := env.do(ctx, tc.caller, http.MethodGet, "/clusters/"+tc.other, nil)
			Expect(other.status).To(Equal(r.status), "%s: another tenant's cluster %s vs a missing ID %s", tc.caller.name, other, r)
			Expect(string(other.body)).To(Equal(string(r.body)), "%s: the bodies tell a missing cluster from another tenant's", tc.caller.name)
		}
	})

	It("8: refuses a caller with no role", func(ctx SpecContext) {
		expectStatus(env.do(ctx, nobodyA, http.MethodGet, "/clusters", nil), http.StatusForbidden, "nobody-a lists clusters")
	})

	It("9: refuses a tenant-scoped list without a tenant, and serves a global one", func(ctx SpecContext) {
		expectStatus(env.do(ctx, noOrg, http.MethodGet, "/clusters", nil), http.StatusForbidden, "no-org lists clusters")
		expectStatus(env.do(ctx, noOrg, http.MethodGet, "/releases", nil), http.StatusOK, "no-org lists releases")
	})

	It("10: refuses a caller claiming the operator tenant from an issuer without operators", func(ctx SpecContext) {
		expectStatus(env.do(ctx, impostor, http.MethodGet, "/clusters", nil), http.StatusForbidden, "impostor lists clusters")
	})

	It("11: gives a fixed-tenant issuer's mapped group its tenant, and an unmapped group nothing", func(ctx SpecContext) {
		r := env.do(ctx, readerB, http.MethodGet, "/clusters", nil)
		expectStatus(r, http.StatusOK, "reader-b lists clusters")
		Expect(listIDs(r, "clusters")).To(Equal(env.tenantIDs(ctx, "clusters", authzTenantB)))
		Expect(listIDs(r, "clusters")).To(BeEmpty(), "%s has no clusters", authzTenantB)

		expectStatus(env.do(ctx, writerB, http.MethodGet, "/clusters", nil), http.StatusForbidden, "writer-b lists clusters")
	})

	It("12: lists every tenant's clusters to an operator", func(ctx SpecContext) {
		r := env.do(ctx, operator, http.MethodGet, "/clusters", nil)
		expectStatus(r, http.StatusOK, "operator lists clusters")
		Expect(listIDs(r, "clusters")).To(Equal(env.tenantIDs(ctx, "clusters", "")))
	})

	It("13: lets a read-only operator read across tenants and not write", func(ctx SpecContext) {
		expectStatus(env.do(ctx, viewerOp, http.MethodGet, "/clusters/"+clusterA, nil), http.StatusOK, "viewer-op gets A")
		expectStatus(env.do(ctx, viewerOp, http.MethodDelete, "/clusters/"+clusterA, nil), http.StatusForbidden, "viewer-op deletes A")
	})

	It("14: keeps a cluster's tenant through an update", func(ctx SpecContext) {
		expectStatus(env.do(ctx, writerA, http.MethodPatch, "/clusters/"+clusterA, map[string]any{"enableCPNodeRecycling": true}),
			http.StatusOK, "writer-a updates A")
		Expect(env.tenantOf(ctx, clusterA)).To(Equal(authzTenantA))
	})

	It("15: lets an operator delete another tenant's cluster", func(ctx SpecContext) {
		expectStatus(env.do(ctx, operator, http.MethodDelete, "/clusters/"+clusterA2, nil), http.StatusAccepted, "operator deletes A2")
		env.terminateWorkflow(ctx, "teardown-cluster-"+clusterA2)
		clusterA2 = ""
	})

	It("17: counts each decision by outcome and action", func(ctx SpecContext) {
		type series struct{ outcome, action string }
		calls := []struct {
			caller authzCaller
			path   string
			want   series
			times  int
		}{
			{writerA, "/clusters/" + clusterA, series{"allow", "getCluster"}, 2},
			{nobodyA, "/clusters", series{"deny", "listClusters"}, 2},
			{writerA2, "/clusters/" + clusterA, series{"not_found", "getCluster"}, 3},
			{noOrg, "/clusters", series{"no_tenant", "listClusters"}, 1},
		}
		count := func() map[series]float64 {
			counts := map[series]float64{}
			for _, c := range calls {
				counts[c.want] = env.metricSum(ctx, authzRequestsMetric, map[string]string{"outcome": c.want.outcome, "action": c.want.action})
			}
			return counts
		}

		before := count()
		for _, c := range calls {
			for range c.times {
				env.do(ctx, c.caller, http.MethodGet, c.path, nil)
			}
		}
		after := count()
		for _, c := range calls {
			Expect(after[c.want]-before[c.want]).To(BeEquivalentTo(c.times),
				"%s{outcome=%q,action=%q} rose by %v; the spec made %d such requests and nothing else should have",
				authzRequestsMetric, c.want.outcome, c.want.action, after[c.want]-before[c.want], c.times)
		}
	})

	Context("when the bundle changes", Ordered, func() {
		var (
			victim   string
			original map[string]string
		)

		// writeProbe asks for an update the handler refuses after authZ:
		// enableEtcdEncryption false is always a 400. So 403 means authZ
		// refused, anything else that it allowed, and nothing changes.
		writeProbe := func(ctx context.Context, caller authzCaller) authzResponse {
			return env.do(ctx, caller, http.MethodPatch, "/clusters/"+victim, map[string]any{"enableEtcdEncryption": false})
		}

		BeforeAll(func(ctx SpecContext) {
			var r authzResponse
			r, victim = env.createCluster(ctx, writerA, "authz-victim-"+uuid.NewString()[:8])
			expectStatus(r, http.StatusCreated, "writer-a creates the victim")

			original = env.bundleConfigMap(ctx).Data
			DeferCleanup(func(ctx SpecContext) {
				env.writeBundleData(ctx, original)
			})
		})

		It("R1: applies a new role mapping without a restart", func(ctx SpecContext) {
			expectStatus(writeProbe(ctx, readerA), http.StatusForbidden, "reader-a's write probe before the change")

			changed, err := withGroupGrants(original, "idp-a", "nvke-readers", []string{"writer"})
			Expect(err).NotTo(HaveOccurred())
			start := time.Now()
			env.writeBundleData(ctx, changed)

			Eventually(func(ctx context.Context) int {
				return writeProbe(ctx, readerA).status
			}).WithContext(ctx).WithTimeout(authzReloadTimeout).WithPolling(2*time.Second).
				ShouldNot(Equal(http.StatusForbidden), "nvke-readers mapped to writer never reached reader-a's decisions")
			delay := time.Since(start).Round(time.Second)
			AddReportEntry("authz reload delay", delay.String())
			GinkgoWriter.Printf("bundle change reached decisions after %s\n", delay)

			expectStatus(env.do(ctx, readerA, http.MethodDelete, "/clusters/"+victim, nil), http.StatusAccepted, "reader-a deletes the victim as a writer")
			env.terminateWorkflow(ctx, "teardown-cluster-"+victim)
		})

		It("R2: keeps the live bundle when a new one fails to load", func(ctx SpecContext) {
			live, err := withGroupGrants(original, "idp-a", "nvke-readers", []string{"writer"})
			Expect(err).NotTo(HaveOccurred())
			broken, err := withGroupGrants(live, "idp-a", "nvke-nobody", []string{"superuser"})
			Expect(err).NotTo(HaveOccurred())

			failedBefore := env.metricSum(ctx, authzReloadsMetric, map[string]string{"result": "failed"})
			env.writeBundleData(ctx, broken)

			Eventually(func(ctx context.Context) float64 {
				return env.metricSum(ctx, authzReloadsMetric, map[string]string{"result": "failed"})
			}).WithContext(ctx).WithTimeout(authzReloadTimeout).WithPolling(2*time.Second).
				Should(BeNumerically(">", failedBefore), "%s{result=\"failed\"} never rose for a bundle granting an undeclared role", authzReloadsMetric)

			Expect(writeProbe(ctx, readerA).status).NotTo(Equal(http.StatusForbidden), "reader-a lost the live mapping to a bundle that failed to load")
			expectStatus(env.do(ctx, nobodyA, http.MethodGet, "/clusters", nil), http.StatusForbidden, "nobody-a gained the undeclared role")
		})

		It("R3: restores the original decisions", func(ctx SpecContext) {
			env.writeBundleData(ctx, original)

			Eventually(func(ctx context.Context) int {
				return writeProbe(ctx, readerA).status
			}).WithContext(ctx).WithTimeout(authzReloadTimeout).WithPolling(2*time.Second).
				Should(Equal(http.StatusForbidden), "the restored bundle never reached reader-a's decisions")

			for _, tc := range []struct {
				caller       authzCaller
				method, path string
				body         any
				want         int
			}{
				{readerA, http.MethodGet, "/clusters/" + clusterA, nil, http.StatusOK},
				{readerA, http.MethodPatch, "/clusters/" + clusterA, map[string]any{"enableCPNodeRecycling": false}, http.StatusForbidden},
				{writerA2, http.MethodGet, "/clusters/" + clusterA, nil, http.StatusNotFound},
				{nobodyA, http.MethodGet, "/clusters", nil, http.StatusForbidden},
				{readerB, http.MethodGet, "/clusters", nil, http.StatusOK},
				{writerB, http.MethodGet, "/clusters", nil, http.StatusForbidden},
				{viewerOp, http.MethodDelete, "/clusters/" + clusterA, nil, http.StatusForbidden},
			} {
				expectStatus(env.do(ctx, tc.caller, tc.method, tc.path, tc.body), tc.want,
					fmt.Sprintf("after restore, %s %s %s", tc.caller.name, tc.method, tc.path))
			}
		})
	})
})
