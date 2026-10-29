// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/uptrace/bun"
)

// TenantQueries look up the tenant that owns an object. A tenant owns a
// cluster, and through it the cluster's node pools, node sets and nodes. Each
// method is one query joined up to the cluster, and returns ErrNotFound when
// the object doesn't exist.
type TenantQueries interface {
	GetClusterTenant(ctx context.Context, id uuid.UUID) (string, error)
	GetNodePoolTenant(ctx context.Context, id uuid.UUID) (string, error)
	GetNodeSetTenant(ctx context.Context, id uuid.UUID) (string, error)
	GetNodeTenant(ctx context.Context, id uuid.UUID) (string, error)
}

func (q *queriesImpl) GetClusterTenant(ctx context.Context, id uuid.UUID) (string, error) {
	return scanTenant(ctx, q.db.NewSelect().TableExpr("clusters AS c").Where("c.id = ?", id))
}

func (q *queriesImpl) GetNodePoolTenant(ctx context.Context, id uuid.UUID) (string, error) {
	return scanTenant(ctx, q.db.NewSelect().TableExpr("node_pools AS np").
		Join("JOIN clusters c ON c.id = np.cluster_id").
		Where("np.id = ?", id))
}

func (q *queriesImpl) GetNodeSetTenant(ctx context.Context, id uuid.UUID) (string, error) {
	return scanTenant(ctx, q.db.NewSelect().TableExpr("node_sets AS ns").
		Join("JOIN node_pools np ON np.id = ns.node_pool_id").
		Join("JOIN clusters c ON c.id = np.cluster_id").
		Where("ns.id = ?", id))
}

func (q *queriesImpl) GetNodeTenant(ctx context.Context, id uuid.UUID) (string, error) {
	return scanTenant(ctx, q.db.NewSelect().TableExpr("nodes AS n").
		Join("JOIN clusters c ON c.id = n.cluster_id").
		Where("n.id = ?", id))
}

// scanTenant reads c.tenant from query, and returns ErrNotFound for no row.
func scanTenant(ctx context.Context, query *bun.SelectQuery) (string, error) {
	var tenant string
	err := query.ColumnExpr("c.tenant").Scan(ctx, &tenant)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNotFound
	}
	return tenant, err
}
