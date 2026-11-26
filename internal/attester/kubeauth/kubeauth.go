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

// Package kubeauth is every credential attester uses: ServiceAccount tokens the
// Kubernetes API server issues (TokenRequest) and checks (TokenReview). attester
// holds no key of its own; the signing key stays in the API server.
package kubeauth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	authenticationv1client "k8s.io/client-go/kubernetes/typed/authentication/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
)

const (
	// ExtraPodName and ExtraPodUID are the TokenReview user.extra keys the API
	// server sets for a token bound to a Pod.
	ExtraPodName = "authentication.kubernetes.io/pod-name"
	ExtraPodUID  = "authentication.kubernetes.io/pod-uid"

	serviceAccountPrefix = "system:serviceaccount:"

	// MinTokenTTL is the shortest lifetime TokenRequest accepts.
	MinTokenTTL = 10 * time.Minute

	// AudienceAPIServer asks Review for the API server's own audiences: the
	// audience of the token every Pod gets mounted by default.
	AudienceAPIServer = ""
)

// ErrNotAuthenticated is returned when the API server rejects a token. Any
// other error from Review means the API server could not be asked.
var ErrNotAuthenticated = errors.New("token not authenticated")

// ServiceAccountUsername is the username the API server gives a
// ServiceAccount's tokens.
func ServiceAccountUsername(namespace, name string) string {
	return serviceAccountPrefix + namespace + ":" + name
}

// Identity is who a token belongs to, as the API server reports it.
type Identity struct {
	Username string
	// Namespace and ServiceAccount are set for ServiceAccount tokens.
	Namespace      string
	ServiceAccount string
	// PodName and PodUID are set for tokens bound to a Pod (every projected
	// ServiceAccount token kubelet mounts is).
	PodName string
	PodUID  types.UID
}

// Reviewer authenticates tokens with the TokenReview API.
type Reviewer struct {
	Client authenticationv1client.TokenReviewsGetter
}

// Review asks the API server whether token is valid for audience
// (AudienceAPIServer: for the API server itself).
func (r *Reviewer) Review(ctx context.Context, token, audience string) (*Identity, error) {
	spec := authenticationv1.TokenReviewSpec{Token: token}
	if audience != AudienceAPIServer {
		spec.Audiences = []string{audience}
	}
	tr, err := r.Client.TokenReviews().Create(ctx, &authenticationv1.TokenReview{Spec: spec}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("token review: %w", err)
	}
	st := tr.Status
	if !st.Authenticated {
		if st.Error != "" {
			return nil, fmt.Errorf("%w: %s", ErrNotAuthenticated, st.Error)
		}
		return nil, ErrNotAuthenticated
	}
	// An authenticator that ignores audiences reports none; that must not pass
	// as "valid for this audience".
	if audience != AudienceAPIServer && !slices.Contains(st.Audiences, audience) {
		return nil, fmt.Errorf("%w: not valid for audience %q", ErrNotAuthenticated, audience)
	}
	id := &Identity{Username: st.User.Username}
	if rest, ok := strings.CutPrefix(id.Username, serviceAccountPrefix); ok {
		id.Namespace, id.ServiceAccount, _ = strings.Cut(rest, ":")
	}
	if v := st.User.Extra[ExtraPodName]; len(v) == 1 {
		id.PodName = v[0]
	}
	if v := st.User.Extra[ExtraPodUID]; len(v) == 1 {
		id.PodUID = types.UID(v[0])
	}
	return id, nil
}

// BoundPod is the Pod a minted token is bound to: the token stops being valid
// once that Pod is gone.
type BoundPod struct {
	Name string
	UID  types.UID
}

// Minter requests tokens for one ServiceAccount with the TokenRequest API.
type Minter struct {
	Client         corev1client.ServiceAccountsGetter
	Namespace      string
	ServiceAccount string
	// Pod, when set, binds every token to that Pod. It must run as
	// ServiceAccount.
	Pod *BoundPod
}

// Mint returns a token for audience that lives ttl (at least MinTokenTTL).
func (m *Minter) Mint(ctx context.Context, audience string, ttl time.Duration) (string, time.Time, error) {
	seconds := int64(max(ttl, MinTokenTTL) / time.Second)
	req := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			Audiences:         []string{audience},
			ExpirationSeconds: &seconds,
		},
	}
	if m.Pod != nil {
		req.Spec.BoundObjectRef = &authenticationv1.BoundObjectReference{
			APIVersion: "v1", Kind: "Pod", Name: m.Pod.Name, UID: m.Pod.UID,
		}
	}
	out, err := m.Client.ServiceAccounts(m.Namespace).CreateToken(ctx, m.ServiceAccount, req, metav1.CreateOptions{})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("token request for %s/%s: %w", m.Namespace, m.ServiceAccount, err)
	}
	return out.Status.Token, out.Status.ExpirationTimestamp.Time, nil
}

// CachedToken hands out one token for a fixed audience and requests a new one
// when less than a fifth of its lifetime is left.
type CachedToken struct {
	Minter   *Minter
	Audience string
	TTL      time.Duration

	mu    sync.Mutex
	token string
	exp   time.Time
	ttl   time.Duration
	now   func() time.Time
}

// Token returns a valid token, minting one if needed.
func (c *CachedToken) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now
	if c.now != nil {
		now = c.now
	}
	if c.token != "" && now().Add(c.ttl/5).Before(c.exp) {
		return c.token, nil
	}
	tok, exp, err := c.Minter.Mint(ctx, c.Audience, c.TTL)
	if err != nil {
		return "", err
	}
	c.token, c.exp, c.ttl = tok, exp, exp.Sub(now())
	return tok, nil
}

// BearerToken returns the token of an "Authorization: Bearer <token>" header.
func BearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) <= len(prefix) || !strings.EqualFold(auth[:len(prefix)], prefix) {
		return "", false
	}
	tok := strings.TrimSpace(auth[len(prefix):])
	return tok, tok != ""
}
