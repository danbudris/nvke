// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dsx-ai-factory/nvke/controller/api"
)

// Every operation in the spec maps to exactly one resource, so a new operation
// fails here until it is given one. An object's ID is read from the request
// type the generated handler passes for that operation.
func TestEveryOperationHasAResource(t *testing.T) {
	t.Parallel()

	actions, err := Actions()
	require.NoError(t, err)
	require.NotEmpty(t, actions)

	server := reflect.TypeFor[api.StrictServerInterface]()
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			t.Parallel()

			_, isCollection := collections[action]
			o, isObject := objects[action]
			require.NotEqual(t, isCollection, isObject, "%s must map to exactly one of a collection and an object", action)
			if !isObject {
				return
			}
			method, ok := server.MethodByName(strings.ToUpper(action[:1]) + action[1:])
			require.True(t, ok, "the strict server has no method for %s", action)
			request := reflect.Zero(method.Type.In(1)).Interface()
			_, ok = o.id(request)
			assert.True(t, ok, "%s reads its ID from a request other than %T", action, request)
		})
	}

	for action := range collections {
		assert.Contains(t, actions, action, "collections maps %s, which the spec doesn't have", action)
	}
	for action := range objects {
		assert.Contains(t, actions, action, "objects maps %s, which the spec doesn't have", action)
	}
}
