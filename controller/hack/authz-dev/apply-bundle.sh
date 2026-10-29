#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Apply the authorization bundle in hack/authz-dev/bundle as ConfigMap
# nvke-authz-bundle, which the controller mounts at /etc/nvke/authz. Tilt runs
# this as the nvke-authz-bundle resource when NKE_AUTHZ_ENABLED is true. A
# change reaches the controller through its reload, after the kubelet's
# ConfigMap sync.
#
# Environment: KUBE_CONTEXT (default: the kubeconfig's current context),
# NVKE_CONTROLLER_NAMESPACE (default nke-controller).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
namespace="${NVKE_CONTROLLER_NAMESPACE:-nke-controller}"

kubectl_cmd=(kubectl)
[[ -n "${KUBE_CONTEXT:-}" ]] && kubectl_cmd+=(--context "${KUBE_CONTEXT}")

"${kubectl_cmd[@]}" -n "${namespace}" create configmap nvke-authz-bundle \
  --from-file=policies.cedar="${here}/bundle/policies.cedar" \
  --from-file=roles.json="${here}/bundle/roles.json" \
  --from-file=authorization.yaml="${here}/bundle/authorization.yaml" \
  --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f -
