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

// Package api is the HTTPS API Pods call with their own ServiceAccount token.
// It authenticates the token with the TokenReview API, finds the Pod and its
// node, forwards the check to the attester agent on that node, and returns the
// answer with an attestation (package attest) the caller can verify with the
// TokenReview API in turn.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/topolvm/topolvm/internal/attester/agent"
	"github.com/topolvm/topolvm/internal/attester/attest"
	"github.com/topolvm/topolvm/internal/attester/config"
	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

// RBAC is in charts/topolvm/templates/attester, not in kubebuilder markers:
// topolvm's `make manifests` would merge markers into topolvm-controller's role.

// Registrar is what the handlers are registered on: the manager's webhook
// server, which is only used as an HTTPS server with a cert-manager
// certificate.
type Registrar interface {
	Register(path string, hook http.Handler)
}

// Authenticator checks a token for an audience (kubeauth.Reviewer).
type Authenticator interface {
	Review(ctx context.Context, token, audience string) (*kubeauth.Identity, error)
}

// Attester attests a result (attest.Attester).
type Attester interface {
	Attest(ctx context.Context, v any) (result, attestation string, err error)
}

// TokenSource hands out the token the attester presents to agents
// (kubeauth.CachedToken).
type TokenSource interface {
	Token(ctx context.Context) (string, error)
}

// Server serves the Pod-facing API.
type Server struct {
	// Reader reads the calling Pod, its PVCs and StorageClasses in any
	// namespace. It should be the manager's API reader so the cache does not
	// have to hold every Pod.
	Reader client.Reader
	// Agents lists the agent Pods in Namespace (the cache is fine here).
	Agents client.Reader
	// Auth authenticates callers (audience config.AudienceAPI).
	Auth Authenticator
	// Attest attests every answer.
	Attest Attester
	// AgentTokens authenticates the attester to agents.
	AgentTokens TokenSource
	// AgentUsername is the agents' ServiceAccount username; only reports it
	// attested are used.
	AgentUsername string
	// Namespace is where the agents run.
	Namespace string
	// AgentPort is the agent's HTTP port.
	AgentPort int
	// VolumeGroup is the volume group the agent checks.
	VolumeGroup string
	// StorageClassName, when set, is the StorageClass a calling Pod must use
	// through a PVC or a generic ephemeral volume.
	StorageClassName string
	// HTTPClient calls the agent; nil means a client with a 3 minute timeout.
	HTTPClient *http.Client
	// now is time.Now outside tests.
	now func() time.Time
}

// Answer is the body of every 200: the exact result bytes and the token that
// attests them.
type Answer struct {
	// Token is "valid" on /handshake, for cache-operator clients.
	Token       string `json:"token,omitempty"`
	Result      string `json:"result"`
	Attestation string `json:"attestation"`
}

// Register adds the handlers: /handshake and one path per check function.
func (s *Server) Register(reg Registrar) {
	reg.Register("/handshake", http.HandlerFunc(s.handshake))
	for _, fn := range config.CheckFunctions {
		reg.Register("/"+fn, s.checkHandler(fn))
	}
}

// handshake answers a valid token with an attested echo of the caller's
// nonce, which is how the caller learns that a real attester is behind the URL.
func (s *Server) handshake(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authenticate(w, r); !ok {
		return
	}
	nonce, ok := s.nonce(w, r)
	if !ok {
		return
	}
	s.answer(w, r, "valid", &attest.Handshake{Use: attest.UseHandshake, Nonce: nonce, IssuedAt: s.clock().Unix()})
}

// checkHandler runs fn against the disks of the calling Pod's node.
func (s *Server) checkHandler(fn string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		logger := log.FromContext(ctx).WithValues("function", fn)

		id, ok := s.authenticate(w, r)
		if !ok {
			return
		}
		nonce, ok := s.nonce(w, r)
		if !ok {
			return
		}
		logger = logger.WithValues("namespace", id.Namespace, "pod", id.PodName)

		pod, err := s.findPod(ctx, id)
		if err != nil {
			logger.Info("calling Pod not found", "error", err.Error())
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		if s.StorageClassName != "" {
			uses, err := s.usesStorageClass(ctx, pod)
			if err != nil {
				logger.Error(err, "cannot read the Pod's volumes")
				writeError(w, http.StatusServiceUnavailable, err.Error())
				return
			}
			if !uses {
				writeError(w, http.StatusForbidden,
					fmt.Sprintf("pod %s/%s has no volume of StorageClass %s", pod.Namespace, pod.Name, s.StorageClassName))
				return
			}
		}
		if pod.Spec.NodeName == "" {
			writeError(w, http.StatusConflict, "pod is not scheduled yet")
			return
		}
		logger = logger.WithValues("node", pod.Spec.NodeName)

		agentPod, err := s.findAgent(ctx, pod.Spec.NodeName)
		if err != nil {
			logger.Error(err, "no agent for the Pod's node")
			writeError(w, http.StatusServiceUnavailable, err.Error())
			return
		}

		res, status, err := s.callAgent(ctx, agentPod, fn)
		if err != nil {
			logger.Error(err, "agent call failed", "agent", agentPod.Name, "status", status)
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}
		check := &attest.Check{
			Use:      attest.UseResult,
			Nonce:    nonce,
			IssuedAt: s.clock().Unix(),
			Pod:      pod.Namespace + "/" + pod.Name,
			Function: fn,
			Node:     pod.Spec.NodeName,
			Disks:    nonNil(res.Disks),
			Results:  nonNil(filterDevices(res.Results, r.URL.Query().Get("devices"))),
		}
		logger.Info("check done", "agent", agentPod.Name, "disks", check.Disks, "results", check.Results)
		s.answer(w, r, "", check)
	})
}

// answer attests v and writes it.
func (s *Server) answer(w http.ResponseWriter, r *http.Request, tokenField string, v any) {
	result, attestation, err := s.Attest.Attest(r.Context(), v)
	if err != nil {
		log.FromContext(r.Context()).Error(err, "attest answer")
		writeError(w, http.StatusInternalServerError, "attest answer")
		return
	}
	writeJSON(w, http.StatusOK, Answer{Token: tokenField, Result: result, Attestation: attestation})
}

// nonce reads the caller's nonce from the query and writes the 400 itself.
func (s *Server) nonce(w http.ResponseWriter, r *http.Request) (string, bool) {
	nonce := r.URL.Query().Get("nonce")
	if err := attest.ValidateNonce(nonce); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return "", false
	}
	return nonce, true
}

// callerAudiences are the token audiences a caller may present, in the order
// they are tried: the Pod's default ServiceAccount token (nothing to configure
// in the Pod), then a projected token for topolvm-attester (keeps the caller's API
// server credential out of attester's hands).
var callerAudiences = []string{kubeauth.AudienceAPIServer, config.AudienceAPI}

// authenticate reviews the Bearer token and writes the 401 itself. Only
// ServiceAccount tokens bound to a Pod are accepted: the Pod is what tells
// attester which node to check.
func (s *Server) authenticate(w http.ResponseWriter, r *http.Request) (*kubeauth.Identity, bool) {
	tok, ok := kubeauth.BearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return nil, false
	}
	var id *kubeauth.Identity
	var err error
	for _, aud := range callerAudiences {
		if id, err = s.Auth.Review(r.Context(), tok, aud); !errors.Is(err, kubeauth.ErrNotAuthenticated) {
			break
		}
	}
	if err != nil {
		if errors.Is(err, kubeauth.ErrNotAuthenticated) {
			log.FromContext(r.Context()).Info("rejected token", "error", err.Error())
			writeError(w, http.StatusUnauthorized, "invalid token")
		} else {
			log.FromContext(r.Context()).Error(err, "token review failed")
			writeError(w, http.StatusServiceUnavailable, "token review failed")
		}
		return nil, false
	}
	if id.Namespace == "" || id.PodName == "" {
		writeError(w, http.StatusUnauthorized, "token is not a ServiceAccount token bound to a Pod")
		return nil, false
	}
	return id, true
}

// findPod returns the Pod the token is bound to, checking its UID so a Pod
// recreated under the same name does not inherit a token.
func (s *Server) findPod(ctx context.Context, id *kubeauth.Identity) (*corev1.Pod, error) {
	var pod corev1.Pod
	err := s.Reader.Get(ctx, types.NamespacedName{Namespace: id.Namespace, Name: id.PodName}, &pod)
	if apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("pod %s/%s does not exist", id.Namespace, id.PodName)
	}
	if err != nil {
		return nil, fmt.Errorf("get pod: %w", err)
	}
	if id.PodUID != "" && pod.UID != id.PodUID {
		return nil, fmt.Errorf("pod %s/%s is not the one the token was issued to", id.Namespace, id.PodName)
	}
	if pod.DeletionTimestamp != nil {
		return nil, fmt.Errorf("pod %s/%s is being deleted", id.Namespace, id.PodName)
	}
	return &pod, nil
}

func (s *Server) clock() time.Time {
	if s.now != nil {
		return s.now()
	}
	return time.Now()
}

func nonNil[T any](v []T) []T {
	if v == nil {
		return []T{}
	}
	return v
}

// findAgent returns the running agent Pod on nodeName.
func (s *Server) findAgent(ctx context.Context, nodeName string) (*corev1.Pod, error) {
	var pods corev1.PodList
	err := s.Agents.List(ctx, &pods, client.InNamespace(s.Namespace),
		client.MatchingLabels{config.AgentLabelKey: config.AgentLabelValue})
	if err != nil {
		return nil, fmt.Errorf("list agent pods: %w", err)
	}
	for i := range pods.Items {
		p := &pods.Items[i]
		if p.Spec.NodeName == nodeName && p.Status.Phase == corev1.PodRunning && p.Status.PodIP != "" &&
			p.DeletionTimestamp == nil {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no running attester agent on node %s", nodeName)
}

// callAgent asks the agent to run fn and returns its verified result, or the
// HTTP status and message of its error.
func (s *Server) callAgent(ctx context.Context, agentPod *corev1.Pod, fn string) (*agent.Result, int, error) {
	agentToken, err := s.AgentTokens.Token(ctx)
	if err != nil {
		return nil, 0, err
	}
	nonce, err := newNonce()
	if err != nil {
		return nil, 0, err
	}
	u := url.URL{
		Scheme:   "http",
		Host:     net.JoinHostPort(agentPod.Status.PodIP, strconv.Itoa(s.AgentPort)),
		Path:     "/v1/check/" + fn,
		RawQuery: url.Values{"vg": {s.VolumeGroup}, "nonce": {nonce}}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+agentToken)

	resp, err := s.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("call agent %s: %w", agentPod.Name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("read agent response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error == "" {
			e.Error = strings.TrimSpace(string(body))
		}
		return nil, resp.StatusCode, fmt.Errorf("agent %s: %s", agentPod.Name, e.Error)
	}
	var ans agent.Answer
	if err := json.Unmarshal(body, &ans); err != nil {
		return nil, resp.StatusCode, fmt.Errorf("decode agent response: %w", err)
	}
	rep, err := s.verifyAgent(ctx, agentPod, fn, nonce, &ans)
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("agent %s: %w", agentPod.Name, err)
	}
	return &rep.Result, resp.StatusCode, nil
}

// verifyAgent accepts an agent's answer only if the API server confirms it
// was attested by the agent ServiceAccount, bound to exactly the agent Pod
// attester called, and the report is for this request and that Pod's node. The
// HTTP hop between agent and attester is not trusted.
func (s *Server) verifyAgent(ctx context.Context, agentPod *corev1.Pod, fn, nonce string, ans *agent.Answer) (*agent.Report, error) {
	id, err := attest.Review(ctx, s.Auth, ans.Result, ans.Attestation)
	if err != nil {
		return nil, err
	}
	switch {
	case id.Username != s.AgentUsername:
		return nil, fmt.Errorf("report attested by %q, not %q", id.Username, s.AgentUsername)
	case id.PodName != agentPod.Name || id.PodUID != agentPod.UID:
		return nil, fmt.Errorf("report attested by pod %q, not the agent pod called", id.PodName)
	}
	var rep agent.Report
	if err := json.Unmarshal([]byte(ans.Result), &rep); err != nil {
		return nil, fmt.Errorf("decode report: %w", err)
	}
	switch {
	case rep.Use != attest.UseAgentResult:
		return nil, fmt.Errorf("report is a %q", rep.Use)
	case rep.Nonce != nonce:
		return nil, errors.New("report nonce does not match")
	case rep.Function != fn:
		return nil, fmt.Errorf("report is for %q, not %q", rep.Function, fn)
	case rep.Node != agentPod.Spec.NodeName:
		return nil, fmt.Errorf("report is for node %q, not %q", rep.Node, agentPod.Spec.NodeName)
	}
	return &rep, nil
}

// newNonce is 32 random bytes as hex, fresh for every agent call.
func newNonce() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random nonce: %w", err)
	}
	return hex.EncodeToString(b), nil
}

func (s *Server) httpClient() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 3 * time.Minute}
}

// filterDevices keeps the results of the devices named in the comma separated
// devices parameter (with or without /dev/). An empty parameter keeps all.
// cache-operator clients send the parameter, so it is honoured.
func filterDevices(results []map[string]string, devices string) []map[string]string {
	if strings.TrimSpace(devices) == "" {
		return results
	}
	want := map[string]bool{}
	for d := range strings.SplitSeq(devices, ",") {
		if d = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(d), "/dev/")); d != "" {
			want[d] = true
		}
	}
	filtered := make([]map[string]string, 0, len(results))
	for _, r := range results {
		for dev := range r {
			if want[strings.TrimPrefix(dev, "/dev/")] {
				filtered = append(filtered, r)
			}
		}
	}
	return filtered
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil && !errors.Is(err, context.Canceled) {
		log.Log.V(1).Info("write response", "error", err.Error())
	}
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
