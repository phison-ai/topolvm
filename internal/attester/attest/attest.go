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

// Package attest makes the API's answers verifiable by the caller (the
// aiDAPTIV middleware, "MW") without attester holding any key.
//
// An answer is two strings: result, the exact JSON bytes of what attester says,
// and attestation, a ServiceAccount token the Kubernetes API server issued to
// attester through the TokenRequest API. The token is bound to the attester Pod and
// its audience is Audience(result), "sha256:<hex of SHA-256(result)>", so it
// vouches for that one result and nothing else. MW checks it with the
// TokenReview API, asking for exactly that audience, and requires the token to
// belong to attester's ServiceAccount. Changing one byte of result changes the
// audience the token would need; producing a token for a new audience takes
// the right to request tokens for attester's ServiceAccount, which only attester (and
// the cluster admin) has.
//
// Every result echoes the nonce MW chose for the request, so a recorded answer
// cannot be replayed.
package attest

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

const (
	// AudiencePrefix starts the audience of every attestation.
	AudiencePrefix = "sha256:"
	// TTL is how long an attestation token lives. TokenRequest does not issue
	// shorter tokens; replay is stopped by the nonce, not by the expiry.
	TTL = kubeauth.MinTokenTTL

	// MinNonceLength and MaxNonceLength bound the nonce the caller supplies.
	MinNonceLength = 16
	MaxNonceLength = 256

	// UseHandshake and UseResult are the values of the use field, so one kind
	// of answer cannot be passed off as the other.
	UseHandshake = "handshake"
	UseResult    = "result"
	// UseAgentResult marks what an agent answers the attester.
	UseAgentResult = "agent-result"
)

// Handshake is the result of /handshake.
type Handshake struct {
	Use      string `json:"use"`
	Nonce    string `json:"nonce"`
	IssuedAt int64  `json:"iat"`
}

// Check is the result of a check endpoint.
type Check struct {
	Use      string `json:"use"`
	Nonce    string `json:"nonce"`
	IssuedAt int64  `json:"iat"`
	// Pod is "<namespace>/<name>" of the caller.
	Pod string `json:"pod"`
	// Function is the Sails function that ran.
	Function string `json:"fn"`
	// Node is the node the devices belong to.
	Node string `json:"node"`
	// Disks are the devices Sails ran against.
	Disks []string `json:"disks"`
	// Results are Sails' answers, one map per device.
	Results []map[string]string `json:"results"`
}

// Audience is the audience an attestation of result carries.
func Audience(result []byte) string {
	sum := sha256.Sum256(result)
	return AudiencePrefix + hex.EncodeToString(sum[:])
}

// nonceRE accepts hex and base64url, which is what any sane client produces.
var nonceRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// ValidateNonce rejects nonces that are too short to be unguessable, too long
// to be reasonable, or not plain hex/base64url.
func ValidateNonce(nonce string) error {
	switch {
	case nonce == "":
		return errors.New("nonce is required")
	case len(nonce) < MinNonceLength:
		return fmt.Errorf("nonce must be at least %d characters", MinNonceLength)
	case len(nonce) > MaxNonceLength:
		return fmt.Errorf("nonce must be at most %d characters", MaxNonceLength)
	case !nonceRE.MatchString(nonce):
		return errors.New("nonce must be hex or base64url")
	}
	return nil
}

// Minter is what an Attester needs from kubeauth.Minter.
type Minter interface {
	Mint(ctx context.Context, audience string, ttl time.Duration) (string, time.Time, error)
}

// Attester produces attestations with attester's ServiceAccount.
type Attester struct {
	Minter Minter
}

// Attest encodes v as the result and requests a token for its audience.
func (a *Attester) Attest(ctx context.Context, v any) (result, attestation string, err error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", "", fmt.Errorf("encode result: %w", err)
	}
	tok, _, err := a.Minter.Mint(ctx, Audience(raw), TTL)
	if err != nil {
		return "", "", err
	}
	return string(raw), tok, nil
}

// Reviewer is what a Verifier needs from kubeauth.Reviewer.
type Reviewer interface {
	Review(ctx context.Context, token, audience string) (*kubeauth.Identity, error)
}

// Verifier is the MW side. attester's tests use it; MW has its own copy
// (docs/topolvm-attester-mw.md spells out the steps).
type Verifier struct {
	Reviewer Reviewer
	// Username is attester's ServiceAccount username,
	// system:serviceaccount:topolvm-system:topolvm-attester.
	Username string
}

// VerifyHandshake checks a /handshake answer for nonce.
func (v *Verifier) VerifyHandshake(ctx context.Context, result, attestation, nonce string) (*Handshake, error) {
	if err := v.verify(ctx, result, attestation); err != nil {
		return nil, err
	}
	var h Handshake
	if err := json.Unmarshal([]byte(result), &h); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	if err := checkUseAndNonce(h.Use, UseHandshake, h.Nonce, nonce); err != nil {
		return nil, err
	}
	return &h, nil
}

// VerifyCheck checks a check answer for nonce, function fn and the caller pod
// ("<namespace>/<name>"). Checking pod stops a relay: another Pod, on a node
// with Phison SSDs, asking attester with the caller's nonce and handing the
// answer over.
func (v *Verifier) VerifyCheck(ctx context.Context, result, attestation, nonce, fn, pod string) (*Check, error) {
	if err := v.verify(ctx, result, attestation); err != nil {
		return nil, err
	}
	var c Check
	if err := json.Unmarshal([]byte(result), &c); err != nil {
		return nil, fmt.Errorf("decode result: %w", err)
	}
	if err := checkUseAndNonce(c.Use, UseResult, c.Nonce, nonce); err != nil {
		return nil, err
	}
	if c.Function != fn {
		return nil, fmt.Errorf("result is for %q, not %q", c.Function, fn)
	}
	if c.Pod != pod {
		return nil, fmt.Errorf("result checked pod %q, not %q", c.Pod, pod)
	}
	return &c, nil
}

// Review checks that attestation vouches for exactly result and returns who
// it was issued to. The caller decides whether that identity is the expected
// one.
func Review(ctx context.Context, r Reviewer, result, attestation string) (*kubeauth.Identity, error) {
	id, err := r.Review(ctx, attestation, Audience([]byte(result)))
	if err != nil {
		return nil, fmt.Errorf("attestation rejected: %w", err)
	}
	return id, nil
}

func (v *Verifier) verify(ctx context.Context, result, attestation string) error {
	id, err := Review(ctx, v.Reviewer, result, attestation)
	if err != nil {
		return err
	}
	if id.Username != v.Username {
		return fmt.Errorf("attestation is from %q, not %q", id.Username, v.Username)
	}
	return nil
}

func checkUseAndNonce(use, wantUse, nonce, wantNonce string) error {
	if use != wantUse {
		return fmt.Errorf("result is a %q, not a %q", use, wantUse)
	}
	if nonce != wantNonce {
		return errors.New("result nonce does not match")
	}
	return nil
}
