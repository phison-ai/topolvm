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

package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/topolvm/topolvm/internal/attester/agent"
	"github.com/topolvm/topolvm/internal/attester/attest"
	"github.com/topolvm/topolvm/internal/attester/config"
	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

type muxRegistrar struct{ *http.ServeMux }

func (m muxRegistrar) Register(path string, h http.Handler) { m.Handle(path, h) }

const (
	attesterNS = "topolvm-system"
	nonce      = "f00dbabef00dbabef00dbabef00dbabe"
	podUID     = types.UID("uid-web-0")
	// Tokens the fake TokenReview knows.
	podToken     = "pod-token"
	defaultToken = "default-token"
	unboundToken = "unbound-token"
	agentToken   = "agent-token"
	agentUser    = "system:serviceaccount:topolvm-system:topolvm-attester-agent"
	// agentAttestPrefix + audience is what the fake agent attests with.
	agentAttestPrefix = "agent-for:"
)

// fakeAuth is TokenReview: a token is valid for exactly one audience.
type fakeAuth struct {
	tokens map[string]struct {
		audience string
		id       kubeauth.Identity
	}
	err error
	// agent is who agent attestations belong to.
	agent kubeauth.Identity
}

func (f *fakeAuth) Review(_ context.Context, token, audience string) (*kubeauth.Identity, error) {
	if f.err != nil {
		return nil, f.err
	}
	if strings.HasPrefix(token, agentAttestPrefix) {
		if token != agentAttestPrefix+audience {
			return nil, kubeauth.ErrNotAuthenticated
		}
		id := f.agent
		return &id, nil
	}
	t, ok := f.tokens[token]
	if !ok || t.audience != audience {
		return nil, kubeauth.ErrNotAuthenticated
	}
	return &t.id, nil
}

// fakeAttester stands in for TokenRequest: the "token" names the audience it
// was requested for, which is all the API code can influence.
type fakeAttester struct{}

func (fakeAttester) Attest(_ context.Context, v any) (string, string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", "", err
	}
	return string(raw), "token-for:" + attest.Audience(raw), nil
}

type staticToken string

func (s staticToken) Token(context.Context) (string, error) { return string(s), nil }

// fixture wires a Server to a fake agent and a fake API server.
type fixture struct {
	auth     *fakeAuth
	api      *httptest.Server
	agent    *httptest.Server
	agentHit int
	// agentStatus and agentBody override the agent's answer when set.
	agentStatus int
	agentBody   string
	// report changes the agent's report before it is attested; tamper
	// changes the attested result bytes afterwards (on the wire).
	report func(*agent.Report)
	tamper func(string) string
}

func newFixture(t *testing.T, objs ...client.Object) *fixture {
	t.Helper()
	f := &fixture{auth: &fakeAuth{tokens: map[string]struct {
		audience string
		id       kubeauth.Identity
	}{
		podToken: {config.AudienceAPI, kubeauth.Identity{
			Username: "system:serviceaccount:team:default", Namespace: "team", ServiceAccount: "default",
			PodName: "web-0", PodUID: podUID,
		}},
		defaultToken: {kubeauth.AudienceAPIServer, kubeauth.Identity{
			Username: "system:serviceaccount:team:default", Namespace: "team", ServiceAccount: "default",
			PodName: "web-0", PodUID: podUID,
		}},
		unboundToken: {config.AudienceAPI, kubeauth.Identity{
			Username: "system:serviceaccount:team:default", Namespace: "team", ServiceAccount: "default",
		}},
		agentToken: {config.AudienceAgent, kubeauth.Identity{Username: "system:serviceaccount:topolvm-system:topolvm-attester"}},
	}, agent: kubeauth.Identity{Username: agentUser, PodName: "topolvm-attester-agent-x", PodUID: "uid-topolvm-attester-agent-x"}}}

	f.agent = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.agentHit++
		if r.Header.Get("Authorization") != "Bearer "+agentToken {
			http.Error(w, "wrong token", http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("vg") != "vg_aidaptiv" {
			http.Error(w, "wrong vg "+r.URL.Query().Get("vg"), http.StatusBadRequest)
			return
		}
		if f.agentStatus != 0 {
			w.WriteHeader(f.agentStatus)
			_, _ = w.Write([]byte(f.agentBody))
			return
		}
		rep := &agent.Report{
			Use: attest.UseAgentResult, Nonce: r.URL.Query().Get("nonce"), IssuedAt: 1, Node: "node-1",
			Function: strings.TrimPrefix(r.URL.Path, "/v1/check/"),
			Result: agent.Result{
				VolumeGroup:     "vg_aidaptiv",
				PhysicalVolumes: []string{"/dev/md127"},
				Disks:           []string{"/dev/nvme0n1", "/dev/nvme1n1"},
				Results:         []map[string]string{{"nvme0n1": "1"}, {"nvme1n1": "1"}},
			},
		}
		if f.report != nil {
			f.report(rep)
		}
		raw, _ := json.Marshal(rep)
		ans := agent.Answer{Result: string(raw), Attestation: agentAttestPrefix + attest.Audience(raw)}
		if f.tamper != nil {
			ans.Result = f.tamper(ans.Result)
		}
		_ = json.NewEncoder(w).Encode(ans)
	}))
	t.Cleanup(f.agent.Close)
	_, portStr, err := net.SplitHostPort(f.agent.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, _ := strconv.Atoi(portStr)

	c := fake.NewClientBuilder().WithScheme(scheme.Scheme).WithObjects(objs...).Build()
	s := &Server{
		Reader:           c,
		Agents:           c,
		Auth:             f.auth,
		Attest:           fakeAttester{},
		AgentTokens:      staticToken(agentToken),
		AgentUsername:    agentUser,
		Namespace:        attesterNS,
		AgentPort:        port,
		VolumeGroup:      "vg_aidaptiv",
		StorageClassName: "aidaptiv-cache",
		HTTPClient:       &http.Client{Timeout: 5 * time.Second},
		now:              func() time.Time { return time.Unix(1_700_000_000, 0) },
	}
	mux := http.NewServeMux()
	s.Register(muxRegistrar{mux})
	f.api = httptest.NewServer(mux)
	t.Cleanup(f.api.Close)
	return f
}

func (f *fixture) get(t *testing.T, path, bearer string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, f.api.URL+path, nil)
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
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// answer decodes a 200 and checks that the attestation was requested for the
// hash of exactly the result bytes returned.
func answer(t *testing.T, body string) Answer {
	t.Helper()
	var a Answer
	if err := json.Unmarshal([]byte(body), &a); err != nil {
		t.Fatalf("body %q: %v", body, err)
	}
	if a.Attestation != "token-for:"+attest.Audience([]byte(a.Result)) {
		t.Fatalf("attestation %q is not for result %q", a.Attestation, a.Result)
	}
	return a
}

func check(t *testing.T, body, fn string) *attest.Check {
	t.Helper()
	var c attest.Check
	if err := json.Unmarshal([]byte(answer(t, body).Result), &c); err != nil {
		t.Fatal(err)
	}
	if c.Use != attest.UseResult || c.Nonce != nonce || c.Function != fn || c.Pod != "team/web-0" || c.IssuedAt == 0 {
		t.Errorf("check = %+v", c)
	}
	return &c
}

// workloadPod is the Pod podToken is bound to, in namespace "team", using an
// aidaptiv-cache PVC, scheduled on node ("" means not scheduled yet).
func workloadPod(node string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "web-0", Namespace: "team", UID: podUID},
		Spec: corev1.PodSpec{
			NodeName: node,
			Volumes: []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{
				PersistentVolumeClaim: &corev1.PersistentVolumeClaimVolumeSource{ClaimName: "cache-web-0"},
			}}},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
}

// pvc is the claim workloadPod mounts, of class ("" means none set).
func pvc(class string) *corev1.PersistentVolumeClaim {
	p := &corev1.PersistentVolumeClaim{ObjectMeta: metav1.ObjectMeta{Name: "cache-web-0", Namespace: "team"}}
	if class != "" {
		p.Spec.StorageClassName = new(class)
	}
	return p
}

func agentPod(name, node, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: name, Namespace: attesterNS, UID: types.UID("uid-" + name),
			Labels: map[string]string{config.AgentLabelKey: config.AgentLabelValue},
		},
		Spec:   corev1.PodSpec{NodeName: node},
		Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: ip},
	}
}

func TestHandshake(t *testing.T) {
	f := newFixture(t)
	path := "/handshake?nonce=" + nonce
	if resp, _ := f.get(t, path, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("no token: %d", resp.StatusCode)
	}
	if resp, _ := f.get(t, path, "garbage"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token: %d", resp.StatusCode)
	}
	if resp, _ := f.get(t, path, agentToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token for another audience accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.get(t, path, unboundToken); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token not bound to a Pod accepted: %d", resp.StatusCode)
	}
	if resp, _ := f.get(t, "/handshake", podToken); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no nonce: %d", resp.StatusCode)
	}
	if resp, _ := f.get(t, "/handshake?nonce=short", podToken); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("short nonce: %d", resp.StatusCode)
	}

	resp, body := f.get(t, path, podToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("handshake = %d %q", resp.StatusCode, body)
	}
	a := answer(t, body)
	var h attest.Handshake
	if err := json.Unmarshal([]byte(a.Result), &h); err != nil {
		t.Fatal(err)
	}
	if a.Token != "valid" || h.Use != attest.UseHandshake || h.Nonce != nonce {
		t.Errorf("answer = %+v, handshake = %+v", a, h)
	}

	f.auth.err = errors.New("apiserver down")
	if resp, _ := f.get(t, path, podToken); resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("TokenReview failure: %d", resp.StatusCode)
	}
}

func TestCheckHappyPath(t *testing.T) {
	f := newFixture(t,
		workloadPod("node-1"),
		pvc("aidaptiv-cache"),
		agentPod("topolvm-attester-agent-x", "node-1", "127.0.0.1"),
		agentPod("topolvm-attester-agent-y", "node-2", "10.0.0.2"),
	)

	for _, fn := range config.CheckFunctions {
		resp, body := f.get(t, "/"+fn+"?nonce="+nonce, podToken)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("/%s = %d %s", fn, resp.StatusCode, body)
		}
		c := check(t, body, fn)
		if len(c.Results) != 2 || c.Results[0]["nvme0n1"] != "1" || c.Results[1]["nvme1n1"] != "1" {
			t.Errorf("/%s results = %v", fn, c.Results)
		}
		if c.Node != "node-1" || len(c.Disks) != 2 {
			t.Errorf("/%s node = %q disks = %v", fn, c.Node, c.Disks)
		}
	}
	// The Pod's default ServiceAccount token works the same, with nothing
	// added to the Pod spec.
	if resp, body := f.get(t, "/support_inference?nonce="+nonce, defaultToken); resp.StatusCode != http.StatusOK {
		t.Fatalf("default token = %d %s", resp.StatusCode, body)
	}
	if f.agentHit != len(config.CheckFunctions)+1 {
		t.Errorf("agent hit %d times", f.agentHit)
	}

	// The devices parameter of cache-operator clients narrows the answer.
	resp, body := f.get(t, "/support_inference?devices=/dev/nvme1n1,nvme9n1&nonce="+nonce, podToken)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("filtered = %d %q", resp.StatusCode, body)
	}
	if results := check(t, body, "support_inference").Results; len(results) != 1 || results[0]["nvme1n1"] != "1" {
		t.Errorf("filtered results = %v", results)
	}

	// Without a nonce there is nothing to attest, and the agent is not asked.
	hits := f.agentHit
	if resp, _ := f.get(t, "/support_inference", podToken); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("no nonce: %d", resp.StatusCode)
	}
	if f.agentHit != hits {
		t.Error("agent called without a nonce")
	}
}

func TestCheckStorageClass(t *testing.T) {
	ephemeral := workloadPod("node-1")
	ephemeral.Spec.Volumes = []corev1.Volume{{Name: "cache", VolumeSource: corev1.VolumeSource{
		Ephemeral: &corev1.EphemeralVolumeSource{VolumeClaimTemplate: &corev1.PersistentVolumeClaimTemplate{
			Spec: corev1.PersistentVolumeClaimSpec{StorageClassName: new("aidaptiv-cache")},
		}},
	}}}
	defaultClass := &storagev1.StorageClass{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aidaptiv-cache", Annotations: map[string]string{isDefaultClassAnnotation: "true"},
		},
		Provisioner: "topolvm.io",
	}
	for name, tc := range map[string]struct {
		objs []client.Object
		want int
	}{
		"other class":             {[]client.Object{workloadPod("node-1"), pvc("standard")}, http.StatusForbidden},
		"PVC missing":             {[]client.Object{workloadPod("node-1")}, http.StatusForbidden},
		"default class":           {[]client.Object{workloadPod("node-1"), pvc(""), defaultClass}, http.StatusOK},
		"generic ephemeral":       {[]client.Object{ephemeral}, http.StatusOK},
		"no class and no default": {[]client.Object{workloadPod("node-1"), pvc("")}, http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, append(tc.objs, agentPod("topolvm-attester-agent-x", "node-1", "127.0.0.1"))...)
			if resp, body := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != tc.want {
				t.Errorf("status = %d %s", resp.StatusCode, body)
			}
		})
	}
}

func TestCheckFailures(t *testing.T) {
	agentOnNode1 := agentPod("topolvm-attester-agent-x", "node-1", "127.0.0.1")
	cache := pvc("aidaptiv-cache")
	t.Run("pod not found", func(t *testing.T) {
		f := newFixture(t, agentOnNode1)
		if resp, _ := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
	t.Run("pod recreated under the same name", func(t *testing.T) {
		p := workloadPod("node-1")
		p.UID = "another-uid"
		f := newFixture(t, p, cache, agentOnNode1)
		if resp, _ := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != http.StatusNotFound {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
	t.Run("pod not scheduled", func(t *testing.T) {
		f := newFixture(t, workloadPod(""), cache, agentOnNode1)
		if resp, _ := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != http.StatusConflict {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
	t.Run("no agent on node", func(t *testing.T) {
		f := newFixture(t, workloadPod("node-1"), cache, agentPod("a", "node-2", "127.0.0.1"))
		if resp, _ := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d", resp.StatusCode)
		}
	})
	t.Run("agent error is reported", func(t *testing.T) {
		f := newFixture(t, workloadPod("node-1"), cache, agentOnNode1)
		f.agentStatus, f.agentBody = http.StatusInternalServerError, `{"error":"volume group vg_aidaptiv has no physical volume"}`
		resp, body := f.get(t, "/mem_buf_set?nonce="+nonce, podToken)
		if resp.StatusCode != http.StatusBadGateway {
			t.Errorf("status = %d", resp.StatusCode)
		}
		var e map[string]string
		if err := json.Unmarshal([]byte(body), &e); err != nil || e["error"] == "" {
			t.Errorf("body = %q", body)
		}
	})
}

// TestAgentReportIsVerified covers the hop the attester does not trust: the
// plain HTTP answer of the agent.
func TestAgentReportIsVerified(t *testing.T) {
	for name, tc := range map[string]struct {
		report func(*agent.Report)
		tamper func(string) string
		agent  *kubeauth.Identity
		want   int
	}{
		"genuine": {want: http.StatusOK},
		"result changed on the wire": {
			tamper: func(s string) string { return strings.Replace(s, `"nvme0n1":"1"`, `"nvme0n1":"0"`, 1) },
			want:   http.StatusBadGateway,
		},
		"old report replayed": {
			report: func(r *agent.Report) { r.Nonce = "00000000000000000000000000000000" },
			want:   http.StatusBadGateway,
		},
		"report about another node": {
			report: func(r *agent.Report) { r.Node = "node-2" },
			want:   http.StatusBadGateway,
		},
		"report for another function": {
			report: func(r *agent.Report) { r.Function = "mem_buf_set" },
			want:   http.StatusBadGateway,
		},
		"attested by the agent Pod of another node": {
			agent: &kubeauth.Identity{Username: agentUser, PodName: "topolvm-attester-agent-y", PodUID: "uid-topolvm-attester-agent-y"},
			want:  http.StatusBadGateway,
		},
		"attested by another ServiceAccount": {
			agent: &kubeauth.Identity{Username: "system:serviceaccount:topolvm-system:impostor",
				PodName: "topolvm-attester-agent-x", PodUID: "uid-topolvm-attester-agent-x"},
			want: http.StatusBadGateway,
		},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, workloadPod("node-1"), pvc("aidaptiv-cache"),
				agentPod("topolvm-attester-agent-x", "node-1", "127.0.0.1"), agentPod("topolvm-attester-agent-y", "node-2", "10.0.0.2"))
			f.report, f.tamper = tc.report, tc.tamper
			if tc.agent != nil {
				f.auth.agent = *tc.agent
			}
			if resp, body := f.get(t, "/support_inference?nonce="+nonce, podToken); resp.StatusCode != tc.want {
				t.Errorf("status = %d %s", resp.StatusCode, body)
			}
		})
	}
}
