// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package scenario is the file format of hack/authz-load: the callers, their
// tokens, and the requests to send with the status each must return. A
// scenario file is JSON or YAML:
//
//	name: s2-correctness
//	callers:
//	  reader-a: {token: eyJ...}
//	requests:
//	  - {name: reader-a get own, caller: reader-a, method: GET, path: /clusters/<id>, expect: 200}
//	  - {name: reader-a delete own, caller: reader-a, method: DELETE, path: /clusters/<id>, expect: 403, weight: 2}
//
// Paths are relative to the base URL, which ends in /api. A request runs
// weight times per pass through the list (default 1).
package scenario

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"sigs.k8s.io/yaml"
)

// Scenario is one load profile.
type Scenario struct {
	Name     string            `json:"name"`
	BaseURL  string            `json:"baseURL,omitempty"`
	Callers  map[string]Caller `json:"callers"`
	Requests []Request         `json:"requests"`
}

// Caller is one identity.
type Caller struct {
	Token string `json:"token"`
}

// Request is one request and the status it must return.
type Request struct {
	// Name groups requests in the report; empty uses "caller method path".
	Name   string          `json:"name,omitempty"`
	Caller string          `json:"caller"`
	Method string          `json:"method"`
	Path   string          `json:"path"`
	Body   json.RawMessage `json:"body,omitempty"`
	Expect int             `json:"expect"`
	Weight int             `json:"weight,omitempty"`
}

// Label is the request's report group.
func (r Request) Label() string {
	if r.Name != "" {
		return r.Name
	}
	return r.Caller + " " + r.Method + " " + r.Path
}

// Load reads and checks a scenario file.
func Load(path string) (*Scenario, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Scenario
	if err := yaml.UnmarshalStrict(raw, &s); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &s, nil
}

// Write writes s as indented JSON, readable only by the owner: it holds tokens.
func Write(path string, s *Scenario) error {
	if err := s.Validate(); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o600)
}

// Validate checks every request names a known caller and an expected status.
func (s *Scenario) Validate() error {
	if len(s.Requests) == 0 {
		return errors.New("no requests")
	}
	var errs []error
	for i, r := range s.Requests {
		if _, ok := s.Callers[r.Caller]; !ok {
			errs = append(errs, fmt.Errorf("requests[%d]: caller %q is not in callers", i, r.Caller))
		}
		switch r.Method {
		case http.MethodGet, http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete:
		default:
			errs = append(errs, fmt.Errorf("requests[%d]: method %q", i, r.Method))
		}
		if !strings.HasPrefix(r.Path, "/") {
			errs = append(errs, fmt.Errorf("requests[%d]: path %q must start with /", i, r.Path))
		}
		if r.Expect < 100 || r.Expect > 599 {
			errs = append(errs, fmt.Errorf("requests[%d]: expect %d is not an HTTP status", i, r.Expect))
		}
		if r.Weight < 0 {
			errs = append(errs, fmt.Errorf("requests[%d]: weight %d is negative", i, r.Weight))
		}
	}
	return errors.Join(errs...)
}

// Expand returns the requests with each repeated weight times.
func (s *Scenario) Expand() []Request {
	var out []Request
	for _, r := range s.Requests {
		n := r.Weight
		if n == 0 {
			n = 1
		}
		for range n {
			out = append(out, r)
		}
	}
	return out
}
