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

package kubeauth

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
)

// reviewWith answers every TokenReview with status.
func reviewWith(status authenticationv1.TokenReviewStatus, err error) (*Reviewer, *authenticationv1.TokenReview) {
	cs := fake.NewClientset()
	var seen authenticationv1.TokenReview
	cs.PrependReactor("create", "tokenreviews", func(a k8stesting.Action) (bool, runtime.Object, error) {
		seen = *a.(k8stesting.CreateAction).GetObject().(*authenticationv1.TokenReview)
		out := seen.DeepCopy()
		out.Status = status
		return true, out, err
	})
	return &Reviewer{Client: cs.AuthenticationV1()}, &seen
}

func TestReview(t *testing.T) {
	ctx := context.Background()

	r, seen := reviewWith(authenticationv1.TokenReviewStatus{
		Authenticated: true,
		Audiences:     []string{"topolvm-attester"},
		User: authenticationv1.UserInfo{
			Username: "system:serviceaccount:team:mw",
			Extra: map[string]authenticationv1.ExtraValue{
				ExtraPodName: {"web-0"}, ExtraPodUID: {"uid-1"},
			},
		},
	}, nil)
	id, err := r.Review(ctx, "tok", "topolvm-attester")
	if err != nil {
		t.Fatal(err)
	}
	if seen.Spec.Token != "tok" || len(seen.Spec.Audiences) != 1 || seen.Spec.Audiences[0] != "topolvm-attester" {
		t.Errorf("review spec = %+v", seen.Spec)
	}
	if id.Namespace != "team" || id.ServiceAccount != "mw" || id.PodName != "web-0" || id.PodUID != "uid-1" {
		t.Errorf("identity = %+v", id)
	}

	r, _ = reviewWith(authenticationv1.TokenReviewStatus{Authenticated: false, Error: "expired"}, nil)
	if _, err := r.Review(ctx, "tok", "topolvm-attester"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("rejected token: %v", err)
	}

	// Authenticated, but the authenticator did not confirm the audience.
	r, _ = reviewWith(authenticationv1.TokenReviewStatus{
		Authenticated: true, User: authenticationv1.UserInfo{Username: "admin"},
	}, nil)
	if _, err := r.Review(ctx, "tok", "topolvm-attester"); !errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("no audience in status: %v", err)
	}

	// AudienceAPIServer leaves spec.audiences empty: the API server's own.
	r, seen = reviewWith(authenticationv1.TokenReviewStatus{
		Authenticated: true, Audiences: []string{"https://kubernetes.default.svc"},
		User: authenticationv1.UserInfo{Username: "system:serviceaccount:team:default",
			Extra: map[string]authenticationv1.ExtraValue{ExtraPodName: {"web-0"}}},
	}, nil)
	if id, err := r.Review(ctx, "tok", AudienceAPIServer); err != nil || id.PodName != "web-0" || len(seen.Spec.Audiences) != 0 {
		t.Errorf("default audience: id=%+v err=%v spec=%+v", id, err, seen.Spec)
	}

	r, _ = reviewWith(authenticationv1.TokenReviewStatus{}, errors.New("connection refused"))
	if _, err := r.Review(ctx, "tok", "topolvm-attester"); err == nil || errors.Is(err, ErrNotAuthenticated) {
		t.Errorf("API error must not look like a rejected token: %v", err)
	}
}

func TestMintAndCache(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	cs := fake.NewClientset()
	var reqs []authenticationv1.TokenRequest
	cs.PrependReactor("create", "serviceaccounts", func(a k8stesting.Action) (bool, runtime.Object, error) {
		ca := a.(k8stesting.CreateAction)
		if ca.GetSubresource() != "token" || ca.GetNamespace() != "topolvm-system" {
			t.Errorf("action = %s %s/%s", ca.GetSubresource(), ca.GetNamespace(), ca.GetResource())
		}
		tr := ca.GetObject().(*authenticationv1.TokenRequest).DeepCopy()
		reqs = append(reqs, *tr)
		tr.Status.Token = "tok-" + string(rune('0'+len(reqs)))
		tr.Status.ExpirationTimestamp = metav1.NewTime(now.Add(time.Duration(*tr.Spec.ExpirationSeconds) * time.Second))
		return true, tr, nil
	})
	m := &Minter{Client: cs.CoreV1(), Namespace: "topolvm-system", ServiceAccount: "topolvm-attester",
		Pod: &BoundPod{Name: "topolvm-attester-0", UID: "uid-0"}}

	// Below the TokenRequest minimum is raised to it.
	if _, _, err := m.Mint(ctx, "aud", time.Minute); err != nil {
		t.Fatal(err)
	}
	spec := reqs[0].Spec
	if *spec.ExpirationSeconds != 600 || spec.Audiences[0] != "aud" ||
		spec.BoundObjectRef == nil || spec.BoundObjectRef.Kind != "Pod" || spec.BoundObjectRef.UID != "uid-0" {
		t.Errorf("token request = %+v", spec)
	}

	c := &CachedToken{Minter: m, Audience: "topolvm-attester-agent", TTL: 10 * time.Minute, now: func() time.Time { return now }}
	first, err := c.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(7 * time.Minute)
	if again, _ := c.Token(ctx); again != first {
		t.Error("token minted again with 3 of 10 minutes left")
	}
	now = now.Add(2 * time.Minute)
	if again, _ := c.Token(ctx); again == first {
		t.Error("token not renewed with 1 of 10 minutes left")
	}
	if len(reqs) != 3 {
		t.Errorf("%d token requests", len(reqs))
	}
}

func TestBearerToken(t *testing.T) {
	for header, want := range map[string]string{"Bearer abc": "abc", "bearer  abc ": "abc", "Basic abc": "", "Bearer ": ""} {
		r, _ := http.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", header)
		if got, _ := BearerToken(r); got != want {
			t.Errorf("BearerToken(%q) = %q, want %q", header, got, want)
		}
	}
}
