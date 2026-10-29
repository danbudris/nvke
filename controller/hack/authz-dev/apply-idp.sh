#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Deploy the authorization dev environment's test IdP (hack/authz-dev/idp.yaml)
# with the material gen.sh writes, and wait for it to serve. Rerunning applies
# no change unless the generated files changed. Tilt runs this as the
# nvke-authz-idp resource when NKE_AUTHZ_ENABLED is true.
#
# Environment: KUBE_CONTEXT (default: the kubeconfig's current context).

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="$("${here}/gen.sh")"
namespace="nvke-authz-idp"

kubectl_cmd=(kubectl)
[[ -n "${KUBE_CONTEXT:-}" ]] && kubectl_cmd+=(--context "${KUBE_CONTEXT}")

"${kubectl_cmd[@]}" apply -f "${here}/idp.yaml"
"${kubectl_cmd[@]}" -n "${namespace}" create secret tls test-idp-tls \
  --cert="${out}/tls.crt" --key="${out}/tls.key" --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f -
"${kubectl_cmd[@]}" -n "${namespace}" create configmap test-idp-jwks \
  --from-file=jwks.json="${out}/jwks.json" --dry-run=client -o yaml | "${kubectl_cmd[@]}" apply -f -

# Mounted Secrets and ConfigMaps update in place, but nginx reads its
# certificate once; a changed checksum rolls the pod.
checksum="$(cat "${out}/tls.crt" "${out}/jwks.json" "${here}/idp.yaml" | shasum -a 256 | cut -c1-16)"
"${kubectl_cmd[@]}" -n "${namespace}" patch deployment test-idp --type merge \
  -p "{\"spec\":{\"template\":{\"metadata\":{\"annotations\":{\"nke.nvidia.com/idp-checksum\":\"${checksum}\"}}}}}"
"${kubectl_cmd[@]}" -n "${namespace}" rollout status deployment/test-idp --timeout=180s
