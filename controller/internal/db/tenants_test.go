// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/uptrace/bun"

	"github.com/dsx-ai-factory/nvke/controller/internal/db"
	"github.com/dsx-ai-factory/nvke/controller/internal/testutil"
)

// tenantTree is one cluster with a node pool, node set and node in it.
type tenantTree struct {
	cluster db.Cluster
	pool    db.NodePool
	set     db.NodeSet
	node    db.Node
}

// seedTenantTree inserts a tenantTree owned by tenant.
func seedTenantTree(ctx context.Context, t *testing.T, bunDB *bun.DB, tenant string) tenantTree {
	t.Helper()
	cluster := newValidCluster(func(c *db.Cluster) { c.Tenant = tenant })
	tree := tenantTree{
		cluster: cluster,
		pool:    db.NodePool{ID: uuid.New(), ClusterID: cluster.ID, Name: "workers", NodeNamePrefix: "w", KubernetesVersion: "1.32.1"},
	}
	tree.set = db.NodeSet{ID: uuid.New(), NodePoolID: tree.pool.ID}
	tree.node = db.Node{ID: uuid.New(), Name: "node-" + tenant, ClusterID: cluster.ID, NodePoolID: tree.pool.ID, NodeSetID: tree.set.ID}
	for _, model := range []any{&tree.cluster, &tree.pool, &tree.set, &tree.node} {
		_, err := bunDB.NewInsert().Model(model).Exec(ctx)
		require.NoError(t, err)
	}
	return tree
}

func TestTenantLookups(t *testing.T) {
	ctx := context.Background()
	bunDB := testutil.SetupDB(ctx, t, (*db.Cluster)(nil), (*db.NodePool)(nil), (*db.NodeSet)(nil), (*db.Node)(nil))
	q := db.NewDB(bunDB)
	a := seedTenantTree(ctx, t, bunDB, "nca-a")
	seedTenantTree(ctx, t, bunDB, "nca-b")

	tests := []struct {
		name   string
		lookup func(context.Context, uuid.UUID) (string, error)
		id     uuid.UUID
	}{
		{name: "cluster", lookup: q.GetClusterTenant, id: a.cluster.ID},
		{name: "node pool", lookup: q.GetNodePoolTenant, id: a.pool.ID},
		{name: "node set", lookup: q.GetNodeSetTenant, id: a.set.ID},
		{name: "node", lookup: q.GetNodeTenant, id: a.node.ID},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tenant, err := tt.lookup(ctx, tt.id)
			require.NoError(t, err)
			assert.Equal(t, "nca-a", tenant)

			_, err = tt.lookup(ctx, uuid.New())
			require.ErrorIs(t, err, db.ErrNotFound)
		})
	}
}

func TestListsFilterByTenant(t *testing.T) {
	ctx := context.Background()
	bunDB := testutil.SetupDB(ctx, t, (*db.Cluster)(nil), (*db.NodePool)(nil), (*db.NodeSet)(nil), (*db.Node)(nil))
	q := db.NewDB(bunDB)
	a := seedTenantTree(ctx, t, bunDB, "nca-a")
	b := seedTenantTree(ctx, t, bunDB, "nca-b")

	// list returns the IDs a list query finds with the tenant filter set to tenant.
	tests := []struct {
		name string
		list func(tenant *string) ([]uuid.UUID, error)
		a, b uuid.UUID
	}{
		{
			name: "clusters",
			list: func(tenant *string) ([]uuid.UUID, error) {
				rows, err := q.ListClusters(ctx, db.ClusterFilters{Tenant: tenant})
				return idsOf(rows, func(c db.Cluster) uuid.UUID { return c.ID }), err
			},
			a: a.cluster.ID, b: b.cluster.ID,
		},
		{
			name: "node pools",
			list: func(tenant *string) ([]uuid.UUID, error) {
				rows, err := q.ListNodePools(ctx, db.NodePoolFilters{Tenant: tenant})
				return idsOf(rows, func(p db.NodePool) uuid.UUID { return p.ID }), err
			},
			a: a.pool.ID, b: b.pool.ID,
		},
		{
			name: "node sets",
			list: func(tenant *string) ([]uuid.UUID, error) {
				rows, err := q.ListNodeSets(ctx, db.NodeSetFilters{Tenant: tenant})
				return idsOf(rows, func(s db.NodeSet) uuid.UUID { return s.ID }), err
			},
			a: a.set.ID, b: b.set.ID,
		},
		{
			name: "nodes",
			list: func(tenant *string) ([]uuid.UUID, error) {
				rows, err := q.ListNodes(ctx, db.NodeFilters{Tenant: tenant})
				return idsOf(rows, func(n db.Node) uuid.UUID { return n.ID }), err
			},
			a: a.node.ID, b: b.node.ID,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.list(testutil.PtrTo("nca-a"))
			require.NoError(t, err)
			assert.Equal(t, []uuid.UUID{tt.a}, got)

			got, err = tt.list(nil)
			require.NoError(t, err)
			assert.ElementsMatch(t, []uuid.UUID{tt.a, tt.b}, got)
		})
	}
}

// UpdateCluster writes every column but tenant, so no update moves a cluster
// to another tenant.
func TestUpdateClusterKeepsTenant(t *testing.T) {
	ctx := context.Background()
	bunDB := testutil.SetupDB(ctx, t, (*db.Cluster)(nil), (*db.NodePool)(nil), (*db.NodeSet)(nil), (*db.Node)(nil))
	q := db.NewDB(bunDB)
	a := seedTenantTree(ctx, t, bunDB, "nca-a")

	stale := a.cluster
	stale.Tenant = "nca-b"
	stale.KubernetesVersion = "1.35"
	updated, err := q.UpdateCluster(ctx, &stale)
	require.NoError(t, err)
	assert.Equal(t, "nca-a", updated.Tenant)

	got, err := q.GetCluster(ctx, a.cluster.ID)
	require.NoError(t, err)
	assert.Equal(t, "1.35", got.KubernetesVersion)
	assert.Equal(t, "nca-a", got.Tenant)
}

func idsOf[T any](rows []T, id func(T) uuid.UUID) []uuid.UUID {
	ids := make([]uuid.UUID, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, id(row))
	}
	return ids
}
