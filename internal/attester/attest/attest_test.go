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

package attest

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	"github.com/topolvm/topolvm/internal/attester/kubeauth"
)

func TestValidateNonce(t *testing.T) {
	for nonce, ok := range map[string]bool{
		"":                                    false,
		"short":                               false,
		strings.Repeat("a", MaxNonceLength+1): false,
		"0123456789abcdef0123456789abcdef":    true,
		"base64url_Value-0123456789":          true,
		"not/base64url+padding=0123456789":    false,
	} {
		if err := ValidateNonce(nonce); (err == nil) != ok {
			t.Errorf("ValidateNonce(%q) = %v, want ok=%v", nonce, err, ok)
		}
	}
}

func TestAudience(t *testing.T) {
	a := Audience([]byte(`{"use":"result"}`))
	if !strings.HasPrefix(a, AudiencePrefix) || len(a) != len(AudiencePrefix)+64 {
		t.Errorf("Audience = %q", a)
	}
	if a == Audience([]byte(`{"use":"result" }`)) {
		t.Error("one byte of difference gave the same audience")
	}
}

// TestRoundTrip runs the whole scheme against a real kube-apiserver: attester
// requests a token bound to its Pod for the hash of a result, and MW reviews
// it. This is what makes an attestation unforgeable without attester's
// ServiceAccount, so it is tested for real, not with a fake.
func TestRoundTrip(t *testing.T) {
	// TopoLVM's Makefile exports ENVTEST_ASSETS_DIR, like its other envtest suites.
	if os.Getenv("ENVTEST_ASSETS_DIR") == "" && os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("neither ENVTEST_ASSETS_DIR nor KUBEBUILDER_ASSETS is set; run through make test")
	}
	env := &envtest.Environment{BinaryAssetsDirectory: os.Getenv("ENVTEST_ASSETS_DIR")}
	cfg, err := env.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = env.Stop() })
	cs, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	const ns = "topolvm-system"
	mustCreate(t, func() error {
		_, err := cs.CoreV1().Namespaces().Create(ctx,
			&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{})
		return err
	})
	for _, sa := range []string{"topolvm-attester", "impostor"} {
		mustCreate(t, func() error {
			_, err := cs.CoreV1().ServiceAccounts(ns).Create(ctx,
				&corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: sa}}, metav1.CreateOptions{})
			return err
		})
	}
	pod, err := cs.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "topolvm-attester-0"},
		Spec: corev1.PodSpec{
			ServiceAccountName:           "topolvm-attester",
			AutomountServiceAccountToken: new(false),
			Containers:                   []corev1.Container{{Name: "manager", Image: "attester"}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}

	minter := &kubeauth.Minter{
		Client: cs.CoreV1(), Namespace: ns, ServiceAccount: "topolvm-attester",
		Pod: &kubeauth.BoundPod{Name: pod.Name, UID: pod.UID},
	}
	attester := &Attester{Minter: minter}
	reviewer := &kubeauth.Reviewer{Client: cs.AuthenticationV1()}
	verifier := &Verifier{Reviewer: reviewer, Username: kubeauth.ServiceAccountUsername(ns, "topolvm-attester")}

	const nonce, fn, caller = "f00dbabef00dbabef00dbabef00dbabe", "support_inference", "team/web-0"
	check := &Check{
		Use: UseResult, Nonce: nonce, IssuedAt: time.Now().Unix(), Pod: "team/web-0",
		Function: "support_inference", Node: "node-1",
		Disks: []string{"/dev/nvme0n1"}, Results: []map[string]string{{"nvme0n1": "1"}},
	}
	result, token, err := attester.Attest(ctx, check)
	if err != nil {
		t.Fatal(err)
	}

	got, err := verifier.VerifyCheck(ctx, result, token, nonce, fn, caller)
	if err != nil {
		t.Fatalf("genuine attestation rejected: %v", err)
	}
	if got.Results[0]["nvme0n1"] != "1" || got.Node != "node-1" {
		t.Errorf("result = %+v", got)
	}
	id, err := reviewer.Review(ctx, token, Audience([]byte(result)))
	if err != nil {
		t.Fatal(err)
	}
	if id.PodName != pod.Name || id.PodUID != pod.UID || id.ServiceAccount != "topolvm-attester" {
		t.Errorf("identity = %+v", id)
	}

	t.Run("tampered result", func(t *testing.T) {
		forged := strings.Replace(result, `"nvme0n1":"1"`, `"nvme0n1":"0"`, 1)
		if forged == result {
			t.Fatal("test did not change the result")
		}
		if _, err := verifier.VerifyCheck(ctx, forged, token, nonce, fn, caller); !errors.Is(err, kubeauth.ErrNotAuthenticated) {
			t.Errorf("tampered result: err = %v", err)
		}
	})
	t.Run("replayed for another nonce", func(t *testing.T) {
		if _, err := verifier.VerifyCheck(ctx, result, token, "00000000000000000000000000000000", fn, caller); err == nil {
			t.Error("accepted for another nonce")
		}
	})
	t.Run("relayed: attester checked another Pod", func(t *testing.T) {
		if _, err := verifier.VerifyCheck(ctx, result, token, nonce, fn, "team/mw-on-plain-ssd"); err == nil {
			t.Error("result for another Pod accepted")
		}
	})
	t.Run("another function", func(t *testing.T) {
		if _, err := verifier.VerifyCheck(ctx, result, token, nonce, "support_finetune", caller); err == nil {
			t.Error("result for another function accepted")
		}
	})
	t.Run("handshake is not a check", func(t *testing.T) {
		if _, err := verifier.VerifyHandshake(ctx, result, token, nonce); err == nil {
			t.Error("a check result passed as a handshake")
		}
	})
	t.Run("token of another ServiceAccount", func(t *testing.T) {
		other := &Attester{Minter: &kubeauth.Minter{Client: cs.CoreV1(), Namespace: ns, ServiceAccount: "impostor"}}
		r, tok, err := other.Attest(ctx, check)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := verifier.VerifyCheck(ctx, r, tok, nonce, fn, caller); err == nil {
			t.Error("attestation by another ServiceAccount accepted")
		}
	})
	t.Run("garbage", func(t *testing.T) {
		if _, err := verifier.VerifyCheck(ctx, result, "not-a-token", nonce, fn, caller); err == nil {
			t.Error("garbage token accepted")
		}
	})
	t.Run("attester Pod deleted", func(t *testing.T) {
		if err := cs.CoreV1().Pods(ns).Delete(ctx, pod.Name, metav1.DeleteOptions{GracePeriodSeconds: ptr.To[int64](0)}); err != nil {
			t.Fatal(err)
		}
		// The API server caches successful reviews for about 10 seconds.
		deadline := time.Now().Add(30 * time.Second)
		for {
			_, err := verifier.VerifyCheck(ctx, result, token, nonce, fn, caller)
			if err != nil {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("attestation still valid after its Pod was deleted")
			}
			time.Sleep(200 * time.Millisecond)
		}
	})
}

func mustCreate(t *testing.T, create func() error) {
	t.Helper()
	if err := create(); err != nil {
		t.Fatal(err)
	}
}
