// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
	"sigs.k8s.io/yaml"

	"github.com/dsx-ai-factory/nvke/controller/test/e2e/internal/authtoken"
	"github.com/dsx-ai-factory/nvke/controller/test/e2e/internal/controller"
	"github.com/dsx-ai-factory/nvke/controller/test/e2e/internal/idptoken"
	"github.com/dsx-ai-factory/nvke/controller/test/e2e/internal/kube"
	"github.com/dsx-ai-factory/nvke/controller/test/e2e/internal/nvke"
)

// Environment for the authz specs. Every default matches controller/Tiltfile
// with NKE_AUTHZ_ENABLED=true.
const (
	// authzRequireEnv turns the "authZ is not deployed" skip into a failure.
	authzRequireEnv = "NKE_E2E_REQUIRE_AUTHZ"
	// authzKeyEnv is the test IdP's signing key, from hack/authz-dev/gen.sh.
	authzKeyEnv     = "NKE_E2E_AUTHZ_KEY"
	authzDefaultKey = "../../.local/authz-dev/signing-key.pem"
	// authzIssuerBaseEnv is the test IdP's URL; each issuer is a path under it.
	authzIssuerBaseEnv     = "NKE_E2E_AUTHZ_ISSUER_BASE"
	authzDefaultIssuerBase = "https://test-idp.nvke-authz-idp.svc"
	// authzCreateBodyEnv names a createCluster body that returns 201 on this
	// site; its name is replaced per create.
	authzCreateBodyEnv     = "NKE_E2E_AUTHZ_CREATE_BODY"
	authzDefaultCreateBody = "testdata/authz-create-cluster.json"
	// authzBundleConfigMapEnv is the ConfigMap the controller mounts at
	// AUTHZ_BUNDLE_DIR, in the controller's namespace.
	authzBundleConfigMapEnv     = "NKE_E2E_AUTHZ_BUNDLE_CONFIGMAP"
	authzDefaultBundleConfigMap = "nvke-authz-bundle"

	// Where the specs read cluster tenants, with psql in the database pod.
	authzPostgresNamespaceEnv = "NKE_E2E_AUTHZ_PG_NAMESPACE"
	authzPostgresPodEnv       = "NKE_E2E_AUTHZ_PG_POD"
	authzPostgresContainerEnv = "NKE_E2E_AUTHZ_PG_CONTAINER"
	authzPostgresDatabaseEnv  = "NKE_E2E_AUTHZ_PG_DATABASE"
)

// authzBundleDirEnv on the controller container turns authZ on.
const authzBundleDirEnv = "AUTHZ_BUNDLE_DIR"

// authzDeniedMessage is the body message of every authZ 403. authN's 403
// says "Not admitted: ...", so the two can't be mistaken.
const authzDeniedMessage = "Not authorized"

// Metric names the controller exports for authZ.
const (
	authzRequestsMetric = "nvke_authz_requests_total"
	authzReloadsMetric  = "nvke_authz_reloads_total"
)

// authzTimeout bounds one request, exec or cluster read.
const authzTimeout = 60 * time.Second

// authzCaller is one identity the specs present.
type authzCaller struct {
	name   string
	tokens nvke.TokenSource
}

// staticToken is a TokenSource for a pre-minted IdP token.
type staticToken string

func (t staticToken) Token(context.Context) (string, error) { return string(t), nil }

// authzEnv is what the authz specs share.
type authzEnv struct {
	restConfig *rest.Config
	clientset  kubernetes.Interface
	api        *kube.ServiceForwarder
	metrics    *kube.ServiceForwarder
	audience   string
	createBody map[string]any
}

// authzDeployed reports whether the controller container sets AUTHZ_BUNDLE_DIR.
func authzDeployed(ctx context.Context, clientset kubernetes.Interface) (bool, error) {
	deployment, err := clientset.AppsV1().Deployments(controller.Namespace()).Get(ctx, controller.Deployment(), metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("getting Deployment %s/%s: %w", controller.Namespace(), controller.Deployment(), err)
	}
	container := controllerContainer(deployment)
	if container == nil {
		return false, fmt.Errorf("deployment %s/%s has no container named %s", controller.Namespace(), controller.Deployment(), controller.Deployment())
	}
	value, _ := containerEnvValue(container, authzBundleDirEnv)
	return strings.TrimSpace(value) != "", nil
}

// authzAbsentf skips, or fails under NKE_E2E_REQUIRE_AUTHZ.
func authzAbsentf(format string, args ...any) {
	GinkgoHelper()
	message := fmt.Sprintf(format, args...)
	required, err := parseRequireEnv(authzRequireEnv, os.Getenv(authzRequireEnv))
	Expect(err).NotTo(HaveOccurred())
	if required {
		Fail(fmt.Sprintf("%s asserts this cluster authorizes, and it does not. %s", authzRequireEnv, message))
	}
	Skip(message)
}

// newAuthzEnv skips unless authN enforces and authZ is on, then builds the
// shared clients.
func newAuthzEnv(ctx context.Context) *authzEnv {
	GinkgoHelper()
	restConfig, clientset := authnCluster()

	audience, found, mode := authnDeployment(ctx, clientset)
	if !found || mode != authnModeEnforcing {
		authzAbsentf("authentication is not enforcing (mode %q), and authorization needs it", mode)
	}
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	deployed, err := authzDeployed(tctx, clientset)
	Expect(err).NotTo(HaveOccurred())
	if !deployed {
		authzAbsentf("authorization is OFF: %s is not set on Deployment %s/%s; run Tilt with NKE_AUTHZ_ENABLED=true",
			authzBundleDirEnv, controller.Namespace(), controller.Deployment())
	}

	metrics, err := kube.SharedServiceForwarder(restConfig, controller.Namespace(), controller.Service(), nvkeControllerMetricsPort)
	Expect(err).NotTo(HaveOccurred(), "build a port-forward to the metrics listener")

	raw, err := os.ReadFile(envOrDefault(authzCreateBodyEnv, authzDefaultCreateBody))
	Expect(err).NotTo(HaveOccurred(), "read the createCluster body (%s)", authzCreateBodyEnv)
	var body map[string]any
	Expect(json.Unmarshal(raw, &body)).To(Succeed(), "parse the createCluster body")

	return &authzEnv{
		restConfig: restConfig,
		clientset:  clientset,
		api:        authnForwarder(restConfig),
		metrics:    metrics,
		audience:   audience,
		createBody: body,
	}
}

// idpCaller mints a token from the test IdP for issuer ("idp-a", "idp-b").
func (e *authzEnv) idpCaller(name, issuer, org string, groups ...string) authzCaller {
	GinkgoHelper()
	key, err := idptoken.LoadKey(envOrDefault(authzKeyEnv, authzDefaultKey))
	Expect(err).NotTo(HaveOccurred(),
		"authorization is on but the test IdP key is not readable; run controller/hack/authz-dev/gen.sh or set %s", authzKeyEnv)
	token, err := idptoken.Mint(key, idptoken.Claims{
		Issuer:   envOrDefault(authzIssuerBaseEnv, authzDefaultIssuerBase) + "/" + issuer,
		Subject:  name,
		Audience: e.audience,
		Groups:   groups,
		Org:      org,
		TTL:      time.Hour,
	})
	Expect(err).NotTo(HaveOccurred(), "mint a token for %s", name)
	return authzCaller{name: name, tokens: staticToken(token)}
}

// saCaller presents a service account token from nke-clients.
func (e *authzEnv) saCaller(name, serviceAccount string) authzCaller {
	GinkgoHelper()
	source, err := authtoken.New(e.clientset, authtoken.Options{
		Namespace:      authtoken.DefaultNamespace,
		ServiceAccount: serviceAccount,
		Audience:       e.audience,
	})
	Expect(err).NotTo(HaveOccurred(), "build the token source for %s", name)
	return authzCaller{name: name, tokens: source}
}

// authzResponse is one API response.
type authzResponse struct {
	status int
	body   []byte
}

func (r authzResponse) String() string { return fmt.Sprintf("%d %s", r.status, r.body) }

// do sends one API request as caller. path is under /api. Only a transport
// error fails; every status is data.
func (e *authzEnv) do(ctx context.Context, caller authzCaller, method, path string, body any) authzResponse {
	GinkgoHelper()
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()

	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		Expect(err).NotTo(HaveOccurred())
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(tctx, method, e.api.BaseURL()+"/api"+path, reader)
	Expect(err).NotTo(HaveOccurred())
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	token, err := caller.tokens.Token(tctx)
	Expect(err).NotTo(HaveOccurred(), "token for %s", caller.name)
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := e.api.HTTPClient().Do(req)
	Expect(err).NotTo(HaveOccurred(), "%s %s as %s", method, path, caller.name)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	Expect(err).NotTo(HaveOccurred())
	return authzResponse{status: resp.StatusCode, body: raw}
}

// expectStatus asserts the status and, for a 403 or 404, the body. The API
// answers 404 with no body (api/openapi.yaml), so a hidden object can't
// differ from a missing one there.
func expectStatus(r authzResponse, want int, what string) {
	GinkgoHelper()
	Expect(r.status).To(Equal(want), "%s: response %s", what, r)
	switch want {
	case http.StatusForbidden:
		expectAuthzDenied(r, what)
	case http.StatusNotFound:
		Expect(r.body).To(BeEmpty(), "%s: a 404 carries no body", what)
	}
}

// expectAuthzDenied asserts an authZ refusal, not authN's admission 403.
func expectAuthzDenied(r authzResponse, what string) {
	GinkgoHelper()
	var decoded struct {
		Message string `json:"message"`
	}
	Expect(json.Unmarshal(r.body, &decoded)).To(Succeed(), "%s: 403 body is not JSON: %s", what, r.body)
	Expect(decoded.Message).NotTo(HavePrefix("Not admitted"), "%s: authN refused this caller, so the authZ case never ran", what)
	Expect(decoded.Message).To(Equal(authzDeniedMessage), "%s: 403 body %s", what, r.body)
}

// listIDs reads the "id" of every item under key in a list response.
func listIDs(r authzResponse, key string) []string {
	GinkgoHelper()
	var decoded map[string][]struct {
		ID string `json:"id"`
	}
	Expect(json.Unmarshal(r.body, &decoded)).To(Succeed(), "list body: %s", r.body)
	items, ok := decoded[key]
	Expect(ok).To(BeTrue(), "list body has no %q: %s", key, r.body)
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, item.ID)
	}
	slices.Sort(ids)
	return ids
}

// createCluster creates a cluster named name as caller and terminates its
// provisioning workflow. It returns the response and the new ID ("" unless 201).
func (e *authzEnv) createCluster(ctx context.Context, caller authzCaller, name string) (authzResponse, string) {
	GinkgoHelper()
	body := make(map[string]any, len(e.createBody))
	for k, v := range e.createBody {
		body[k] = v
	}
	body["name"] = name
	r := e.do(ctx, caller, http.MethodPost, "/clusters", body)
	if r.status != http.StatusCreated {
		return r, ""
	}
	var created struct {
		ID string `json:"id"`
	}
	Expect(json.Unmarshal(r.body, &created)).To(Succeed())
	Expect(created.ID).NotTo(BeEmpty(), "201 body carries no id: %s", r.body)
	e.terminateWorkflow(ctx, "provision-cluster-"+created.ID)
	return r, created.ID
}

// nodePoolBody is a schema-valid createNodePool body for clusterID, built from
// the createCluster body's NICo settings.
func (e *authzEnv) nodePoolBody(clusterID string) map[string]any {
	GinkgoHelper()
	cp, _ := e.createBody["controlPlaneConfig"].(map[string]any)
	nico, _ := cp["nico"].(map[string]any)
	types, _ := nico["instanceTypePreference"].([]any)
	Expect(types).NotTo(BeEmpty(), "the createCluster body has no controlPlaneConfig.nico.instanceTypePreference")
	return map[string]any{
		"clusterID":        clusterID,
		"name":             "authz-np",
		"nodeNamePrefix":   "authz-np",
		"desiredNodeCount": 0,
		"nico": map[string]any{
			"instanceTypeID": types[0],
			"release":        nico["release"],
			"subnetIDs":      nico["subnetIDs"],
		},
	}
}

// exec runs command in a container and returns stdout.
func (e *authzEnv) exec(ctx context.Context, namespace, pod, container string, command []string) (string, string, error) {
	req := e.clientset.CoreV1().RESTClient().Post().
		Resource("pods").Namespace(namespace).Name(pod).
		SubResource("exec").
		VersionedParams(&corev1.PodExecOptions{
			Container: container,
			Command:   command,
			Stdout:    true,
			Stderr:    true,
		}, clientgoscheme.ParameterCodec)
	executor, err := remotecommand.NewSPDYExecutor(e.restConfig, http.MethodPost, req.URL())
	if err != nil {
		return "", "", err
	}
	var stdout, stderr bytes.Buffer
	err = executor.StreamWithContext(ctx, remotecommand.StreamOptions{Stdout: &stdout, Stderr: &stderr})
	return stdout.String(), stderr.String(), err
}

// psql runs one query in the controller's database and returns its rows,
// unaligned and tuples only.
func (e *authzEnv) psql(ctx context.Context, query string) []string {
	GinkgoHelper()
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	script := `PGPASSWORD="$(cat "$POSTGRES_PASSWORD_FILE")" exec psql -v ON_ERROR_STOP=1 -U postgres -d "$1" -Atc "$2"`
	stdout, stderr, err := e.exec(tctx,
		envOrDefault(authzPostgresNamespaceEnv, "postgres"),
		envOrDefault(authzPostgresPodEnv, "postgres-postgresql-0"),
		envOrDefault(authzPostgresContainerEnv, "postgresql"),
		[]string{"sh", "-c", script, "psql", envOrDefault(authzPostgresDatabaseEnv, "nke-controller"), query})
	Expect(err).NotTo(HaveOccurred(), "psql %q: %s", query, stderr)
	var rows []string
	for _, line := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if line != "" {
			rows = append(rows, line)
		}
	}
	slices.Sort(rows)
	return rows
}

// tenantOf reads a cluster's stored tenant.
func (e *authzEnv) tenantOf(ctx context.Context, clusterID string) string {
	GinkgoHelper()
	Expect(clusterID).To(MatchRegexp(`^[0-9a-f-]{36}$`))
	rows := e.psql(ctx, fmt.Sprintf("select tenant from clusters where id = '%s'", clusterID))
	Expect(rows).To(HaveLen(1), "cluster %s in the database", clusterID)
	return rows[0]
}

// tenantIDs returns the IDs in table whose cluster is in tenant, or every ID
// when tenant is "".
func (e *authzEnv) tenantIDs(ctx context.Context, table, tenant string) []string {
	GinkgoHelper()
	Expect(tenant).To(MatchRegexp(`^[a-z0-9-]*$`))
	var query string
	switch table {
	case "clusters":
		query = "select c.id from clusters c"
	case "node_pools", "nodes":
		query = fmt.Sprintf("select t.id from %s t join clusters c on c.id = t.cluster_id", table)
	default:
		Fail("unknown table " + table)
	}
	if tenant != "" {
		query += fmt.Sprintf(" where c.tenant = '%s'", tenant)
	}
	rows := e.psql(ctx, query)
	if rows == nil {
		rows = []string{}
	}
	return rows
}

// terminateWorkflow ends a workflow the spec's create or delete started, so
// none keeps retrying against fake infrastructure. The outbox starts it
// asynchronously, so "not found" is retried for a while.
func (e *authzEnv) terminateWorkflow(ctx context.Context, workflowID string) {
	GinkgoHelper()
	namespace := envOrDefault("TEMPORAL_K8S_NAMESPACE", "temporal")
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	pods, err := e.clientset.CoreV1().Pods(namespace).List(tctx, metav1.ListOptions{
		LabelSelector: "app.kubernetes.io/component=admintools",
	})
	Expect(err).NotTo(HaveOccurred())
	var pod string
	for _, p := range pods.Items {
		if p.Status.Phase == corev1.PodRunning {
			pod = p.Name
			break
		}
	}
	Expect(pod).NotTo(BeEmpty(), "no running Temporal admin-tools pod in %s", namespace)

	command := []string{
		"temporal", "workflow", "terminate",
		"--namespace", envOrDefault("E2E_TEMPORAL_NAMESPACE", "nke-controller"),
		"--address", envOrDefault("E2E_TEMPORAL_ADDRESS", "temporal-frontend."+namespace+".svc.cluster.local:7233"),
		"--workflow-id", workflowID,
		"--reason", "authz e2e: no infrastructure behind this cluster",
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		stdout, stderr, err := e.exec(tctx, namespace, pod, envOrDefault("TEMPORAL_ADMIN_TOOLS_CONTAINER", "admin-tools"), command)
		output := strings.ToLower(stdout + stderr)
		switch {
		case err == nil, strings.Contains(output, "already completed"):
			return
		case strings.Contains(output, "not found") && time.Now().Before(deadline):
			time.Sleep(2 * time.Second)
			continue
		default:
			GinkgoWriter.Printf("terminate %s: %v: %s\n", workflowID, err, strings.TrimSpace(stdout+stderr))
			return
		}
	}
}

// metricSum adds up every sample of name whose labels include want.
func (e *authzEnv) metricSum(ctx context.Context, name string, want map[string]string) float64 {
	GinkgoHelper()
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	status, body, err := e.metrics.Get(tctx, metricsPath)
	Expect(err).NotTo(HaveOccurred(), "GET %s", metricsPath)
	Expect(status).To(Equal(http.StatusOK), "GET %s: %s", metricsPath, body)
	total, err := sumMetric(string(body), name, want)
	Expect(err).NotTo(HaveOccurred())
	return total
}

// sumMetric adds up every sample of name in a text exposition whose labels
// include every pair in want. No matching sample is zero.
func sumMetric(exposition, name string, want map[string]string) (float64, error) {
	total := 0.0
	for _, line := range strings.Split(exposition, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		labels := map[string]string{}
		tail := strings.TrimPrefix(line, name)
		if strings.HasPrefix(tail, "{") {
			end := strings.LastIndex(tail, "}")
			if end < 0 {
				return 0, fmt.Errorf("malformed exposition line %q", line)
			}
			for _, pair := range strings.Split(tail[1:end], ",") {
				key, value, ok := strings.Cut(pair, "=")
				if !ok {
					continue
				}
				unquoted, err := strconv.Unquote(value)
				if err != nil {
					return 0, fmt.Errorf("label %q in %q: %w", pair, line, err)
				}
				labels[strings.TrimSpace(key)] = unquoted
			}
			tail = tail[end+1:]
		}
		match := true
		for k, v := range want {
			if labels[k] != v {
				match = false
				break
			}
		}
		if !match {
			continue
		}
		fields := strings.Fields(tail)
		if len(fields) == 0 {
			return 0, fmt.Errorf("malformed exposition line %q", line)
		}
		value, err := strconv.ParseFloat(fields[0], 64)
		if err != nil {
			return 0, fmt.Errorf("value of %q: %w", line, err)
		}
		total += value
	}
	return total, nil
}

// bundleConfigMap reads the authZ bundle ConfigMap's data.
func (e *authzEnv) bundleConfigMap(ctx context.Context) *corev1.ConfigMap {
	GinkgoHelper()
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	cm, err := e.clientset.CoreV1().ConfigMaps(controller.Namespace()).Get(tctx,
		envOrDefault(authzBundleConfigMapEnv, authzDefaultBundleConfigMap), metav1.GetOptions{})
	Expect(err).NotTo(HaveOccurred(), "read the authZ bundle ConfigMap")
	return cm
}

// writeBundleData replaces the bundle ConfigMap's data.
func (e *authzEnv) writeBundleData(ctx context.Context, data map[string]string) {
	GinkgoHelper()
	tctx, cancel := context.WithTimeout(ctx, authzTimeout)
	defer cancel()
	cm := e.bundleConfigMap(ctx)
	cm.Data = data
	_, err := e.clientset.CoreV1().ConfigMaps(controller.Namespace()).Update(tctx, cm, metav1.UpdateOptions{})
	Expect(err).NotTo(HaveOccurred(), "update the authZ bundle ConfigMap")
}

// withGroupGrants returns data with issuer's mapping for the groups claim
// value group granting grants, replacing an existing mapping or adding one.
func withGroupGrants(data map[string]string, issuer, group string, grants []string) (map[string]string, error) {
	var config map[string]any
	if err := yaml.Unmarshal([]byte(data["authorization.yaml"]), &config); err != nil {
		return nil, err
	}
	issuers, _ := config["issuers"].(map[string]any)
	entry, ok := issuers[issuer].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("authorization.yaml has no issuer %q", issuer)
	}
	claims, _ := entry["claims"].([]any)
	grantList := make([]any, 0, len(grants))
	for _, g := range grants {
		grantList = append(grantList, g)
	}
	replaced := false
	for _, c := range claims {
		m, _ := c.(map[string]any)
		if m["name"] == "groups" && m["value"] == group {
			m["grants"] = grantList
			replaced = true
		}
	}
	if !replaced {
		claims = append(claims, map[string]any{"name": "groups", "value": group, "grants": grantList})
	}
	entry["claims"] = claims
	out, err := yaml.Marshal(config)
	if err != nil {
		return nil, err
	}
	changed := make(map[string]string, len(data))
	for k, v := range data {
		changed[k] = v
	}
	changed["authorization.yaml"] = string(out)
	if changed["authorization.yaml"] == data["authorization.yaml"] {
		return nil, errors.New("the edit changed nothing")
	}
	return changed, nil
}

func TestSumMetric(t *testing.T) {
	exposition := `# HELP nvke_authz_requests_total x
# TYPE nvke_authz_requests_total counter
nvke_authz_requests_total{action="getCluster",outcome="allow"} 3
nvke_authz_requests_total{action="getCluster",outcome="not_found"} 2
nvke_authz_requests_total{action="listClusters",outcome="allow"} 1
nvke_authz_requests_total_other{action="getCluster",outcome="allow"} 100
nvke_authz_reloads_total{result="failed"} 4
`
	for _, tc := range []struct {
		name string
		want map[string]string
		sum  float64
	}{
		{authzRequestsMetric, map[string]string{"action": "getCluster", "outcome": "allow"}, 3},
		{authzRequestsMetric, map[string]string{"outcome": "allow"}, 4},
		{authzRequestsMetric, nil, 6},
		{authzRequestsMetric, map[string]string{"outcome": "deny"}, 0},
		{authzReloadsMetric, map[string]string{"result": "failed"}, 4},
	} {
		got, err := sumMetric(exposition, tc.name, tc.want)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.sum {
			t.Fatalf("sumMetric(%s, %v) = %v, want %v", tc.name, tc.want, got, tc.sum)
		}
	}
}

func TestWithGroupGrants(t *testing.T) {
	data := map[string]string{"authorization.yaml": `apiVersion: auth.nvke.nvidia.com/v1alpha1
kind: AuthorizationConfiguration
issuers:
  idp-a:
    tenant: {claim: org}
    claims:
      - {name: groups, value: nvke-readers, grants: [reader]}
`, "roles.json": "[]"}

	changed, err := withGroupGrants(data, "idp-a", "nvke-readers", []string{"writer"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(changed["authorization.yaml"], "- writer") || strings.Contains(changed["authorization.yaml"], "- reader") {
		t.Fatalf("grants not replaced:\n%s", changed["authorization.yaml"])
	}
	if changed["roles.json"] != "[]" || !strings.Contains(data["authorization.yaml"], "[reader]") {
		t.Fatal("the input or another key changed")
	}

	added, err := withGroupGrants(data, "idp-a", "nvke-nobody", []string{"superuser"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(added["authorization.yaml"], "nvke-nobody") || !strings.Contains(added["authorization.yaml"], "nvke-readers") {
		t.Fatalf("mapping not added:\n%s", added["authorization.yaml"])
	}

	if _, err := withGroupGrants(data, "idp-z", "x", nil); err == nil {
		t.Fatal("expected an error for an unknown issuer")
	}
}
