/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package agent

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/topolvm/topolvm/internal/attester/attest"
	"github.com/topolvm/topolvm/internal/attester/config"
	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

const attester = "system:serviceaccount:topolvm-system:topolvm-attester"

// fakeAuth is TokenReview: token -> (audience, username).
type fakeAuth map[string][2]string

func (f fakeAuth) Review(_ context.Context, token, audience string) (*kubeauth.Identity, error) {
	t, ok := f[token]
	if !ok || t[0] != audience {
		return nil, kubeauth.ErrNotAuthenticated
	}
	return &kubeauth.Identity{Username: t[1]}, nil
}

// fakeAttester records the audience it would have requested a token for.
type fakeAttester struct{}

func (fakeAttester) Attest(_ context.Context, v any) (string, string, error) {
	raw, err := json.Marshal(v)
	return string(raw), "token-for:" + attest.Audience(raw), err
}

func TestServer(t *testing.T) {
	fe := &fakeExec{pvs: pvsReport, sails: "nvme0n1: 1\nnvme1n1: 1\n"}
	const agentToken, podToken, strangerToken = "agent", "pod", "stranger"
	srv := &Server{
		Checker: newChecker(t, fe),
		Auth: fakeAuth{
			agentToken:    {config.AudienceAgent, attester},
			podToken:      {config.AudienceAPI, attester},
			strangerToken: {config.AudienceAgent, "system:serviceaccount:team:default"},
		},
		Attester:           attester,
		Attest:             fakeAttester{},
		NodeName:           "node-1",
		DefaultVolumeGroup: "vg_aidaptiv",
	}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	get := func(path, bearer string) *http.Response {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, ts.URL+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if bearer != "" {
			req.Header.Set("Authorization", "Bearer "+bearer)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	if resp := get("/healthz", ""); resp.StatusCode != http.StatusOK {
		t.Errorf("healthz = %d", resp.StatusCode)
	}
	if resp := get("/v1/check/support_inference", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d", resp.StatusCode)
	}
	if resp := get("/v1/check/support_inference", podToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token for the API audience accepted by agent: %d", resp.StatusCode)
	}
	if resp := get("/v1/check/support_inference", strangerToken); resp.StatusCode != http.StatusForbidden {
		t.Errorf("another ServiceAccount accepted by agent: %d", resp.StatusCode)
	}
	if resp := get("/v1/check/rm_rf?nonce=0123456789abcdef0123456789abcdef", agentToken); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unknown function: %d", resp.StatusCode)
	}

	const nonce = "0123456789abcdef0123456789abcdef"
	if resp := get("/v1/check/support_inference", agentToken); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no nonce: %d", resp.StatusCode)
	}
	resp := get("/v1/check/support_inference?nonce="+nonce, agentToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("check = %d", resp.StatusCode)
	}
	var ans Answer
	if err := json.NewDecoder(resp.Body).Decode(&ans); err != nil {
		t.Fatal(err)
	}
	if ans.Attestation != "token-for:"+attest.Audience([]byte(ans.Result)) {
		t.Errorf("attestation %q is not for result %q", ans.Attestation, ans.Result)
	}
	var rep Report
	if err := json.NewDecoder(strings.NewReader(ans.Result)).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if rep.Use != attest.UseAgentResult || rep.Nonce != nonce || rep.Node != "node-1" || rep.Function != "support_inference" ||
		rep.VolumeGroup != "vg_aidaptiv" || len(rep.Results) != 2 || rep.Results[0]["nvme0n1"] != "1" {
		t.Errorf("report = %+v", rep)
	}

	// ?vg= overrides the default.
	if resp := get("/v1/check/mem_buf_cpy?vg=vg_other&nonce="+nonce, agentToken); resp.StatusCode != http.StatusOK {
		t.Errorf("check with vg = %d", resp.StatusCode)
	}
	last := fe.calls[len(fe.calls)-2]
	found := false
	for _, a := range last {
		if a == "vg_name=vg_other" {
			found = true
		}
	}
	if !found {
		t.Errorf("pvs was not run for vg_other: %v", last)
	}
}
