// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Command authz-load drives the NVKE API with a scenario file
// (hack/authz-load/scenario) and checks every response's status against the
// one the scenario expects. Workers take requests from the scenario in turn,
// so the mix holds at any concurrency.
//
//	go run ./hack/authz-load --scenario .local/authz-load/s2.json --concurrency 32 --duration 60s
//
// It reports the total, requests per second, p50/p95/p99 latency, a status
// histogram, the 5xx and transport-error counts, and the mismatches with the
// first ten examples, overall and per request name. It exits 1 when any
// response mismatched, returned 5xx or failed, unless --fail-on-mismatch=false.
// hack/authz-load/gen writes the scenario files.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"text/tabwriter"
	"time"

	"github.com/dsx-ai-factory/nvke/controller/hack/authz-load/scenario"
)

const (
	// maxExamples bounds the mismatch and error examples kept.
	maxExamples = 10
)

func main() {
	failed, err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "authz-load:", err)
		os.Exit(2)
	}
	if failed {
		os.Exit(1)
	}
}

// prepared is a request ready to send.
type prepared struct {
	label, method, url, auth string
	body                     []byte
	expect                   int
}

// sample is one response.
type sample struct {
	label   string
	latency time.Duration
	status  int // 0 for a transport error
}

// Example is one mismatch or error, for the report.
type Example struct {
	Request string `json:"request"`
	Expect  int    `json:"expect"`
	Status  int    `json:"status,omitempty"`
	Body    string `json:"body,omitempty"`
	Error   string `json:"error,omitempty"`
}

// Latency is a latency summary in milliseconds.
type Latency struct {
	P50 float64 `json:"p50Ms"`
	P95 float64 `json:"p95Ms"`
	P99 float64 `json:"p99Ms"`
	Max float64 `json:"maxMs"`
}

// Group is the per-request-name part of the report.
type Group struct {
	Name       string  `json:"name"`
	Count      int     `json:"count"`
	Mismatches int     `json:"mismatches"`
	Latency    Latency `json:"latency"`
}

// Report is the run's result.
type Report struct {
	Scenario    string         `json:"scenario"`
	Concurrency int            `json:"concurrency"`
	Duration    float64        `json:"durationSeconds"`
	Total       int            `json:"total"`
	RPS         float64        `json:"rps"`
	Latency     Latency        `json:"latency"`
	Statuses    map[string]int `json:"statuses"`
	Status5xx   int            `json:"status5xx"`
	Errors      int            `json:"errors"`
	Mismatches  int            `json:"mismatches"`
	Examples    []Example      `json:"examples"`
	Groups      []Group        `json:"groups"`
}

func run() (bool, error) {
	scenarioPath := flag.String("scenario", "", "scenario file (JSON or YAML); required")
	concurrency := flag.Int("concurrency", 32, "concurrent workers")
	duration := flag.Duration("duration", 60*time.Second, "how long to send requests")
	baseURL := flag.String("base-url", "", "API base URL ending in /api (default: the scenario's baseURL, else http://localhost:8080/api)")
	timeout := flag.Duration("timeout", 10*time.Second, "per-request timeout")
	jsonOut := flag.String("json", "", "also write the report as JSON to this file")
	failOnMismatch := flag.Bool("fail-on-mismatch", true, "exit 1 on any mismatch, 5xx or transport error")
	flag.Parse()

	if *scenarioPath == "" {
		return false, errors.New("--scenario is required")
	}
	if *concurrency < 1 || *duration <= 0 {
		return false, errors.New("--concurrency and --duration must be positive")
	}
	s, err := scenario.Load(*scenarioPath)
	if err != nil {
		return false, err
	}
	base := strings.TrimRight(firstNonEmpty(*baseURL, s.BaseURL, "http://localhost:8080/api"), "/")

	var requests []prepared
	for _, r := range s.Expand() {
		requests = append(requests, prepared{
			label:  r.Label(),
			method: r.Method,
			url:    base + r.Path,
			auth:   "Bearer " + s.Callers[r.Caller].Token,
			body:   r.Body,
			expect: r.Expect,
		})
	}

	client := &http.Client{
		Timeout: *timeout,
		Transport: &http.Transport{
			MaxIdleConns:        *concurrency * 2,
			MaxIdleConnsPerHost: *concurrency * 2,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	var (
		next     atomic.Uint64
		mu       sync.Mutex
		examples []Example
		samples  = make([][]sample, *concurrency)
		wg       sync.WaitGroup
	)
	record := func(e Example) {
		mu.Lock()
		defer mu.Unlock()
		if len(examples) < maxExamples {
			examples = append(examples, e)
		}
	}

	start := time.Now()
	deadline := start.Add(*duration)
	for w := range *concurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				p := requests[(next.Add(1)-1)%uint64(len(requests))]
				smp, example := send(client, p)
				samples[w] = append(samples[w], smp)
				if example != nil {
					record(*example)
				}
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	report := summarize(s.Name, *concurrency, elapsed, slices.Concat(samples...), requests)
	report.Examples = examples
	if report.Examples == nil {
		report.Examples = []Example{}
	}
	printReport(os.Stdout, report)
	if *jsonOut != "" {
		raw, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return false, err
		}
		if err := os.WriteFile(*jsonOut, append(raw, '\n'), 0o600); err != nil {
			return false, err
		}
	}
	return *failOnMismatch && (report.Mismatches > 0 || report.Status5xx > 0 || report.Errors > 0), nil
}

// send makes one request. It returns an example when the response is a
// mismatch or the request failed.
func send(client *http.Client, p prepared) (sample, *Example) {
	var body io.Reader
	if len(p.body) > 0 {
		body = bytes.NewReader(p.body)
	}
	req, err := http.NewRequestWithContext(context.Background(), p.method, p.url, body)
	if err != nil {
		return sample{label: p.label}, &Example{Request: p.label, Expect: p.expect, Error: err.Error()}
	}
	req.Header.Set("Authorization", p.auth)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	begin := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return sample{label: p.label, latency: time.Since(begin)}, &Example{Request: p.label, Expect: p.expect, Error: err.Error()}
	}
	excerpt, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	smp := sample{label: p.label, latency: time.Since(begin), status: resp.StatusCode}
	if resp.StatusCode != p.expect {
		return smp, &Example{Request: p.label, Expect: p.expect, Status: resp.StatusCode, Body: string(excerpt)}
	}
	return smp, nil
}

func summarize(name string, concurrency int, elapsed time.Duration, all []sample, requests []prepared) Report {
	expect := map[string]int{}
	for _, p := range requests {
		expect[p.label] = p.expect
	}
	r := Report{
		Scenario:    name,
		Concurrency: concurrency,
		Duration:    elapsed.Seconds(),
		Total:       len(all),
		RPS:         float64(len(all)) / elapsed.Seconds(),
		Statuses:    map[string]int{},
	}
	var latencies []time.Duration
	byLabel := map[string][]sample{}
	for _, s := range all {
		byLabel[s.label] = append(byLabel[s.label], s)
		if s.status == 0 {
			r.Errors++
			continue
		}
		latencies = append(latencies, s.latency)
		r.Statuses[fmt.Sprint(s.status)]++
		if s.status >= 500 {
			r.Status5xx++
		}
		if s.status != expect[s.label] {
			r.Mismatches++
		}
	}
	r.Latency = summarizeLatency(latencies)

	labels := make([]string, 0, len(byLabel))
	for label := range byLabel {
		labels = append(labels, label)
	}
	sort.Strings(labels)
	for _, label := range labels {
		g := Group{Name: label, Count: len(byLabel[label])}
		var ls []time.Duration
		for _, s := range byLabel[label] {
			if s.status == 0 {
				continue
			}
			if s.status != expect[label] {
				g.Mismatches++
			}
			ls = append(ls, s.latency)
		}
		g.Latency = summarizeLatency(ls)
		r.Groups = append(r.Groups, g)
	}
	return r
}

func summarizeLatency(ls []time.Duration) Latency {
	if len(ls) == 0 {
		return Latency{}
	}
	slices.Sort(ls)
	ms := func(d time.Duration) float64 { return float64(d.Microseconds()) / 1000 }
	at := func(q float64) float64 {
		i := int(q*float64(len(ls))+0.5) - 1
		return ms(ls[min(max(i, 0), len(ls)-1)])
	}
	return Latency{P50: at(0.50), P95: at(0.95), P99: at(0.99), Max: ms(ls[len(ls)-1])}
}

func printReport(w io.Writer, r Report) {
	statuses := make([]string, 0, len(r.Statuses))
	for status := range r.Statuses {
		statuses = append(statuses, status)
	}
	sort.Strings(statuses)
	histogram := make([]string, 0, len(statuses))
	for _, status := range statuses {
		histogram = append(histogram, fmt.Sprintf("%s: %d", status, r.Statuses[status]))
	}

	fmt.Fprintf(w, "scenario     %s\n", r.Scenario)
	fmt.Fprintf(w, "concurrency  %d\n", r.Concurrency)
	fmt.Fprintf(w, "duration     %.1fs\n", r.Duration)
	fmt.Fprintf(w, "total        %d\n", r.Total)
	fmt.Fprintf(w, "rps          %.1f\n", r.RPS)
	fmt.Fprintf(w, "latency      p50 %.2fms  p95 %.2fms  p99 %.2fms  max %.2fms\n", r.Latency.P50, r.Latency.P95, r.Latency.P99, r.Latency.Max)
	fmt.Fprintf(w, "statuses     %s\n", strings.Join(histogram, "  "))
	fmt.Fprintf(w, "5xx          %d\n", r.Status5xx)
	fmt.Fprintf(w, "errors       %d\n", r.Errors)
	fmt.Fprintf(w, "mismatches   %d\n", r.Mismatches)
	for _, e := range r.Examples {
		if e.Error != "" {
			fmt.Fprintf(w, "  %s: want %d, error %s\n", e.Request, e.Expect, e.Error)
		} else {
			fmt.Fprintf(w, "  %s: want %d, got %d %s\n", e.Request, e.Expect, e.Status, strings.TrimSpace(e.Body))
		}
	}

	fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "request\tcount\tmismatches\tp50ms\tp95ms\tp99ms")
	for _, g := range r.Groups {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%.2f\t%.2f\t%.2f\n", g.Name, g.Count, g.Mismatches, g.Latency.P50, g.Latency.P95, g.Latency.P99)
	}
	_ = tw.Flush()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
