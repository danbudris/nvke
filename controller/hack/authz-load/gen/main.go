// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command gen seeds the clusters the authZ load scenarios read and writes the
// scenario files hack/authz-load runs:
//
//	s1-overhead.json     only requests allowed with authZ on and off:
//	                     same-tenant get and list, operator get and list
//	s2-correctness.json  every caller, gets and lists, and deletes only where
//	                     authZ refuses them (another tenant's: 404; a reader's
//	                     or a read-only operator's: 403). Run it with authZ ON:
//	                     with authZ off its deletes succeed.
//
// It creates --per-tenant clusters each in nca-a (as writer-a), nca-a2 (as
// writer-a2) and nca-op (as the operator, nke-clients/nke-client), named
// load-<tenant>-NN, through the API, and reuses any that exist. Seed with authZ
// on: with it off a create stores no tenant. Then it terminates the creates'
// provisioning workflows, so none runs during measurement, and prints how many
// workflows are still running; --terminate-all-running terminates those too.
//
// Run from controller/, with Tilt up (NKE_AUTHZ_ENABLED=true) and the API
// port-forwarded on localhost:8080:
//
//	go run ./hack/authz-load/gen
//	go run ./hack/authz-load --scenario .local/authz-load/s2-correctness.json
//
// The files hold bearer tokens valid for --ttl, so they are written 0600 into
// the gitignored .local/authz-load.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/dsx-ai-factory/nvke/controller/hack/authz-dev/idp"
	"github.com/dsx-ai-factory/nvke/controller/hack/authz-load/scenario"
)

// Tenants, issuers and groups, from hack/authz-dev/bundle/authorization.yaml.
const (
	tenantA       = "nca-a"
	tenantA2      = "nca-a2"
	tenantOp      = "nca-op"
	issuerA       = "idp-a"
	issuerB       = "idp-b"
	groupReaders  = "nvke-readers"
	groupWriters  = "nvke-writers" //nolint:gosec // a group name, not a credential
	groupNobody   = "nvke-nobody"
	clustersPath  = "/clusters"
	clusterPrefix = "/clusters/"
)

type options struct {
	baseURL, outDir, keyPath, audience, createBody, kubeContext string
	perTenant                                                   int
	ttl                                                         time.Duration
	terminateAllRunning                                         bool
}

func main() {
	var o options
	flag.StringVar(&o.baseURL, "base-url", "http://localhost:8080/api", "API base URL")
	flag.StringVar(&o.outDir, "out-dir", ".local/authz-load", "where to write the scenario files")
	flag.StringVar(&o.keyPath, "key", idp.DefaultKeyPath, "test IdP signing key")
	flag.StringVar(&o.audience, "audience", "https://nke.tilt.local", "token audience")
	flag.StringVar(&o.createBody, "create-body", "test/e2e/testdata/authz-create-cluster.json", "a createCluster body that returns 201 here; its name is replaced")
	flag.StringVar(&o.kubeContext, "kube-context", "", "kubectl context (default: current)")
	flag.IntVar(&o.perTenant, "per-tenant", 20, "clusters per tenant")
	flag.DurationVar(&o.ttl, "ttl", 4*time.Hour, "lifetime of the tokens written into the scenarios")
	flag.BoolVar(&o.terminateAllRunning, "terminate-all-running", false, "also terminate every other running workflow in the nvke-controller namespace")
	flag.Parse()

	if err := run(context.Background(), o); err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

// tenantSeed is one tenant's seeded clusters and the caller that creates them.
type tenantSeed struct {
	tenant, creator string
	ids             []string
}

func run(ctx context.Context, o options) error {
	callers, err := mintCallers(ctx, o)
	if err != nil {
		return err
	}
	api := &apiClient{base: strings.TrimRight(o.baseURL, "/"), http: &http.Client{Timeout: 30 * time.Second}, callers: callers}

	rawBody, err := os.ReadFile(o.createBody)
	if err != nil {
		return err
	}
	var body map[string]any
	if err := json.Unmarshal(rawBody, &body); err != nil {
		return fmt.Errorf("parse %s: %w", o.createBody, err)
	}

	existing, err := api.clusterNames(ctx, "operator")
	if err != nil {
		return err
	}
	seeds := []*tenantSeed{
		{tenant: tenantA, creator: "writer-a"},
		{tenant: tenantA2, creator: "writer-a2"},
		{tenant: tenantOp, creator: "operator"},
	}
	var created []string
	for _, seed := range seeds {
		for i := range o.perTenant {
			name := fmt.Sprintf("load-%s-%02d", seed.tenant, i)
			if id, ok := existing[name]; ok {
				seed.ids = append(seed.ids, id)
				continue
			}
			body["name"] = name
			id, err := api.create(ctx, seed.creator, body)
			if err != nil {
				return fmt.Errorf("create %s as %s: %w", name, seed.creator, err)
			}
			seed.ids = append(seed.ids, id)
			created = append(created, id)
		}
		fmt.Fprintf(os.Stdout, "%s: %d clusters\n", seed.tenant, len(seed.ids))
	}
	fmt.Fprintf(os.Stdout, "created %d clusters\n", len(created))

	for _, id := range created {
		if err := terminate(ctx, o.kubeContext, "provision-cluster-"+id); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
	if o.terminateAllRunning {
		if out, err := temporal(ctx, o.kubeContext, "workflow", "terminate", "--query", "ExecutionStatus='Running'",
			"--reason", "authz load: no workflow runs during measurement", "--yes"); err != nil {
			fmt.Fprintf(os.Stderr, "warning: terminate every running workflow: %v: %s\n", err, out)
		}
	}
	if out, err := temporal(ctx, o.kubeContext, "workflow", "count", "--query", "ExecutionStatus='Running'"); err == nil {
		fmt.Fprintf(os.Stdout, "running workflows in nvke-controller: %s\n", strings.TrimSpace(out))
	} else {
		fmt.Fprintf(os.Stderr, "warning: count running workflows: %v: %s\n", err, out)
	}

	if err := os.MkdirAll(o.outDir, 0o700); err != nil {
		return err
	}
	a, a2, op := seeds[0].ids, seeds[1].ids, seeds[2].ids
	for file, s := range map[string]*scenario.Scenario{
		"s1-overhead.json":    s1(callers, a, a2, op),
		"s2-correctness.json": s2(callers, a, a2, op),
	} {
		s.BaseURL = o.baseURL
		path := filepath.Join(o.outDir, file)
		if err := scenario.Write(path, s); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Fprintf(os.Stdout, "wrote %s: %d requests per pass\n", path, len(s.Expand()))
	}
	return nil
}

// mintCallers returns every caller's token: IdP callers signed with the test
// IdP key, service accounts from the TokenRequest API.
func mintCallers(ctx context.Context, o options) (map[string]scenario.Caller, error) {
	key, err := idp.LoadKey(o.keyPath)
	if err != nil {
		return nil, err
	}
	callers := map[string]scenario.Caller{}
	for _, c := range []struct {
		name, issuer, org, group string
	}{
		{"reader-a", issuerA, tenantA, groupReaders},
		{"writer-a", issuerA, tenantA, groupWriters},
		{"writer-a2", issuerA, tenantA2, groupWriters},
		{"nobody-a", issuerA, tenantA, groupNobody},
		{"no-org", issuerA, "", groupWriters},
		{"impostor", issuerA, tenantOp, groupWriters},
		{"reader-b", issuerB, "", groupReaders},
		{"writer-b", issuerB, "", groupWriters},
	} {
		token, err := idp.Mint(key, idp.Claims{
			Issuer: c.issuer, Subject: c.name, Groups: []string{c.group}, Org: c.org, Audience: o.audience, TTL: o.ttl,
		})
		if err != nil {
			return nil, err
		}
		callers[c.name] = scenario.Caller{Token: token}
	}
	for name, sa := range map[string]string{"operator": "nke-client", "viewer-op": "nke-viewer"} {
		out, err := kubectl(ctx, o.kubeContext, "-n", "nke-clients", "create", "token", sa,
			"--audience", o.audience, "--duration", o.ttl.String())
		if err != nil {
			return nil, fmt.Errorf("mint a token for %s: %w: %s", sa, err, out)
		}
		callers[name] = scenario.Caller{Token: strings.TrimSpace(out)}
	}
	return callers, nil
}

func s1(callers map[string]scenario.Caller, a, a2, op []string) *scenario.Scenario {
	s := &scenario.Scenario{Name: "s1-overhead", Callers: callers}
	add := func(name, caller, path string, weight int) {
		s.Requests = append(s.Requests, scenario.Request{
			Name: name, Caller: caller, Method: http.MethodGet, Path: path, Expect: http.StatusOK, Weight: weight,
		})
	}
	for _, id := range a {
		add("reader-a get own", "reader-a", clusterPrefix+id, 1)
	}
	add("reader-a list clusters", "reader-a", clustersPath, 5)
	for _, id := range a2 {
		add("writer-a2 get own", "writer-a2", clusterPrefix+id, 1)
	}
	add("writer-a2 list clusters", "writer-a2", clustersPath, 5)
	for _, ids := range [][]string{a, a2, op} {
		for _, id := range ids {
			add("operator get", "operator", clusterPrefix+id, 1)
		}
	}
	add("operator list clusters", "operator", clustersPath, 15)
	return s
}

func s2(callers map[string]scenario.Caller, a, a2, op []string) *scenario.Scenario {
	s := &scenario.Scenario{Name: "s2-correctness", Callers: callers}
	each := func(name, caller, method string, ids []string, expect int) {
		for _, id := range ids {
			s.Requests = append(s.Requests, scenario.Request{Name: name, Caller: caller, Method: method, Path: clusterPrefix + id, Expect: expect})
		}
	}
	one := func(name, caller, path string, expect, weight int) {
		s.Requests = append(s.Requests, scenario.Request{Name: name, Caller: caller, Method: http.MethodGet, Path: path, Expect: expect, Weight: weight})
	}
	const (
		get    = http.MethodGet
		del    = http.MethodDelete
		ok     = http.StatusOK
		denied = http.StatusForbidden
		hidden = http.StatusNotFound
	)
	missing := []string{uuid.NewString()}

	each("reader-a get own", "reader-a", get, a, ok)
	each("reader-a get a2's", "reader-a", get, a2, hidden)
	each("reader-a get op's", "reader-a", get, op, hidden)
	each("reader-a delete own", "reader-a", del, a, denied)
	each("reader-a delete a2's", "reader-a", del, a2, hidden)
	one("reader-a list clusters", "reader-a", clustersPath, ok, 4)
	one("reader-a list releases", "reader-a", "/releases", ok, 2)

	each("writer-a get own", "writer-a", get, a, ok)
	each("writer-a get a2's", "writer-a", get, a2, hidden)
	each("writer-a delete a2's", "writer-a", del, a2, hidden)
	each("writer-a get missing", "writer-a", get, missing, hidden)
	one("writer-a list clusters", "writer-a", clustersPath, ok, 4)

	each("writer-a2 get own", "writer-a2", get, a2, ok)
	each("writer-a2 get a's", "writer-a2", get, a, hidden)
	each("writer-a2 delete a's", "writer-a2", del, a, hidden)
	one("writer-a2 list clusters", "writer-a2", clustersPath, ok, 4)

	each("nobody-a get own tenant's", "nobody-a", get, a, denied)
	one("nobody-a list clusters", "nobody-a", clustersPath, denied, 4)

	each("no-org get a's", "no-org", get, a, denied)
	one("no-org list clusters", "no-org", clustersPath, denied, 4)
	one("no-org list releases", "no-org", "/releases", ok, 2)

	each("impostor get op's", "impostor", get, op, denied)
	one("impostor list clusters", "impostor", clustersPath, denied, 4)

	each("reader-b get a's", "reader-b", get, a, hidden)
	one("reader-b list clusters", "reader-b", clustersPath, ok, 4)

	each("writer-b get a's", "writer-b", get, a, hidden)
	one("writer-b list clusters", "writer-b", clustersPath, denied, 4)

	each("operator get", "operator", get, append(append(append([]string{}, a...), a2...), op...), ok)
	each("operator get missing", "operator", get, missing, hidden)
	one("operator list clusters", "operator", clustersPath, ok, 4)

	each("viewer-op get", "viewer-op", get, a, ok)
	each("viewer-op delete op's", "viewer-op", del, op, denied)
	one("viewer-op list clusters", "viewer-op", clustersPath, ok, 4)
	return s
}

// apiClient calls the NVKE API as a named caller.
type apiClient struct {
	base    string
	http    *http.Client
	callers map[string]scenario.Caller
}

func (c *apiClient) do(ctx context.Context, caller, method, path string, body any) (int, []byte, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.callers[caller].Token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	return resp.StatusCode, raw, err
}

// clusterNames lists the clusters caller can see, by name.
func (c *apiClient) clusterNames(ctx context.Context, caller string) (map[string]string, error) {
	status, raw, err := c.do(ctx, caller, http.MethodGet, clustersPath, nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("list clusters as %s: %d %s", caller, status, raw)
	}
	var list struct {
		Clusters []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"clusters"`
	}
	if err := json.Unmarshal(raw, &list); err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, cl := range list.Clusters {
		names[cl.Name] = cl.ID
	}
	return names, nil
}

func (c *apiClient) create(ctx context.Context, caller string, body map[string]any) (string, error) {
	status, raw, err := c.do(ctx, caller, http.MethodPost, clustersPath, body)
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("%d %s", status, raw)
	}
	var created struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &created); err != nil || created.ID == "" {
		return "", fmt.Errorf("201 without an id: %s", raw)
	}
	return created.ID, nil
}

func kubectl(ctx context.Context, kubeContext string, args ...string) (string, error) {
	if kubeContext != "" {
		args = append([]string{"--context", kubeContext}, args...)
	}
	out, err := exec.CommandContext(ctx, "kubectl", args...).CombinedOutput()
	return string(out), err
}

// temporal runs the temporal CLI in the admin-tools pod against nvke-controller.
func temporal(ctx context.Context, kubeContext string, args ...string) (string, error) {
	full := append([]string{"-n", "temporal", "exec", "deploy/temporal-admintools", "--", "temporal"}, args...)
	full = append(full, "--namespace", "nvke-controller", "--address", "temporal-frontend:7233")
	return kubectl(ctx, kubeContext, full...)
}

// terminate ends one workflow. The outbox starts it asynchronously, so "not
// found" is retried for a minute.
func terminate(ctx context.Context, kubeContext, workflowID string) error {
	deadline := time.Now().Add(time.Minute)
	for {
		out, err := temporal(ctx, kubeContext, "workflow", "terminate", "--workflow-id", workflowID,
			"--reason", "authz load: no infrastructure behind this cluster")
		lower := strings.ToLower(out)
		switch {
		case err == nil, strings.Contains(lower, "already completed"):
			return nil
		case strings.Contains(lower, "not found") && time.Now().Before(deadline):
			time.Sleep(2 * time.Second)
		default:
			return fmt.Errorf("terminate %s: %w: %s", workflowID, err, strings.TrimSpace(out))
		}
	}
}
