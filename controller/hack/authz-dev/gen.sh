#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Generate the authorization dev environment's test IdP material into
# controller/.local/authz-dev (gitignored). Existing files are kept, so a rerun
# changes nothing; delete the directory to start over.
#
#   signing-key.pem  ES256 (P-256) token signing key; hack/authz-dev/mint and the
#                    e2e suite (NKE_E2E_AUTHZ_KEY) sign with it
#   jwks.json        the key's public half, kid = RFC 7638 thumbprint
#   ca.crt, ca.key   self-signed CA; ca.crt is the issuers' jwks.caBundle
#   tls.crt, tls.key the IdP's serving certificate, for test-idp.nvke-authz-idp.svc
#
# Usage: hack/authz-dev/gen.sh [output-dir]

set -euo pipefail

controller_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
out="${1:-${controller_dir}/.local/authz-dev}"
mkdir -p "${out}"
chmod 700 "${out}"

service="test-idp"
namespace="nvke-authz-idp"

if [[ ! -f "${out}/signing-key.pem" ]]; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${out}/signing-key.pem" 2>/dev/null
  chmod 600 "${out}/signing-key.pem"
  rm -f "${out}/jwks.json"
fi

if [[ ! -f "${out}/jwks.json" ]]; then
  (cd "${controller_dir}" && go run ./hack/authz-dev/mint --key "${out}/signing-key.pem" --jwks) > "${out}/jwks.json.tmp"
  mv "${out}/jwks.json.tmp" "${out}/jwks.json"
fi

if [[ ! -f "${out}/ca.crt" || ! -f "${out}/ca.key" ]]; then
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${out}/ca.key" -out "${out}/ca.crt" -days 3650 \
    -subj "/CN=nvke-authz-dev test IdP CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
  chmod 600 "${out}/ca.key"
  rm -f "${out}/tls.crt" "${out}/tls.key"
fi

if [[ ! -f "${out}/tls.crt" || ! -f "${out}/tls.key" ]]; then
  sans="DNS:${service}.${namespace}.svc,DNS:${service}.${namespace}.svc.cluster.local,DNS:${service}.${namespace},DNS:localhost,IP:127.0.0.1"
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -keyout "${out}/tls.key" -out "${out}/tls.csr" \
    -subj "/CN=${service}.${namespace}.svc" 2>/dev/null
  printf 'subjectAltName=%s\nbasicConstraints=CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\n' "${sans}" > "${out}/tls.ext"
  openssl x509 -req -in "${out}/tls.csr" -CA "${out}/ca.crt" -CAkey "${out}/ca.key" -CAcreateserial \
    -out "${out}/tls.crt" -days 825 -extfile "${out}/tls.ext" 2>/dev/null
  chmod 600 "${out}/tls.key"
  rm -f "${out}/tls.csr" "${out}/tls.ext" "${out}/ca.srl"
fi

echo "${out}"
