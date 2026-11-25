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
	"errors"
	"net/http"
	"time"

	"sigs.k8s.io/controller-runtime/pkg/log"

	"github.com/topolvm/topolvm/internal/attester/attest"
	"github.com/topolvm/topolvm/internal/attester/config"
	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

// Authenticator checks a token for an audience (kubeauth.Reviewer).
type Authenticator interface {
	Review(ctx context.Context, token, audience string) (*kubeauth.Identity, error)
}

// Attester attests a result (attest.Attester with the agent's own
// ServiceAccount, bound to the agent Pod).
type Attester interface {
	Attest(ctx context.Context, v any) (result, attestation string, err error)
}

// Answer is the body of a successful check: the exact Report bytes and the
// token that attests them, as in the attester's own API.
type Answer struct {
	Result      string `json:"result"`
	Attestation string `json:"attestation"`
}

// Server is the agent's HTTP API, called by the attester only.
//
//	GET /healthz
//	GET /v1/check/{function}?vg=<volume group>&nonce=<nonce>   Authorization: Bearer <agent token>
//
// The answer is attested like the attester's (package attest), so a check
// result cannot be changed on the Pod network between agent and attester.
type Server struct {
	Checker *Checker
	// Auth reviews the caller's token (audience topolvm-attester-agent).
	Auth Authenticator
	// Attester is the only username accepted: the attester's ServiceAccount,
	// system:serviceaccount:<namespace>:topolvm-attester.
	Attester string
	// Attest attests every answer.
	Attest Attester
	// NodeName is the node the agent runs on; it goes into every Report.
	NodeName string
	// DefaultVolumeGroup is used when the request names none.
	DefaultVolumeGroup string
	// now is time.Now outside tests.
	now func() time.Time
}

// Handler returns the HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /v1/check/{function}", s.check)
	return mux
}

func (s *Server) check(w http.ResponseWriter, r *http.Request) {
	logger := log.FromContext(r.Context())

	tok, ok := kubeauth.BearerToken(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing bearer token")
		return
	}
	id, err := s.Auth.Review(r.Context(), tok, config.AudienceAgent)
	switch {
	case errors.Is(err, kubeauth.ErrNotAuthenticated):
		logger.Info("rejected agent token", "error", err.Error())
		writeError(w, http.StatusUnauthorized, "invalid token")
		return
	case err != nil:
		logger.Error(err, "token review failed")
		writeError(w, http.StatusServiceUnavailable, "token review failed")
		return
	case id.Username != s.Attester:
		logger.Info("rejected caller", "username", id.Username)
		writeError(w, http.StatusForbidden, "only topolvm-attester may call the agent")
		return
	}

	fn := r.PathValue("function")
	if !config.IsCheckFunction(fn) {
		writeError(w, http.StatusNotFound, "unknown check function "+fn)
		return
	}
	nonce := r.URL.Query().Get("nonce")
	if err := attest.ValidateNonce(nonce); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	vg := r.URL.Query().Get("vg")
	if vg == "" {
		vg = s.DefaultVolumeGroup
	}

	res, err := s.Checker.Run(r.Context(), fn, vg)
	if err != nil {
		logger.Error(err, "check failed", "function", fn, "volumeGroup", vg)
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	now := time.Now
	if s.now != nil {
		now = s.now
	}
	result, attestation, err := s.Attest.Attest(r.Context(), &Report{
		Use: attest.UseAgentResult, Nonce: nonce, IssuedAt: now().Unix(), Node: s.NodeName, Function: fn, Result: *res,
	})
	if err != nil {
		logger.Error(err, "attest result")
		writeError(w, http.StatusInternalServerError, "attest result")
		return
	}
	logger.Info("check done", "function", fn, "volumeGroup", vg, "disks", res.Disks, "results", res.Results)
	writeJSON(w, http.StatusOK, Answer{Result: result, Attestation: attestation})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
