package solver

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubefake "k8s.io/client-go/kubernetes/fake"
)

const (
	testNamespace = "cert-manager"
	testKey       = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"
	revokedToken  = "rdns_revoked_token_value"
)

// harness is a solver wired to the go-client fake and a fake Kubernetes
// API holding the token Secret.
type harness struct {
	fake   *rdnstest.Fake
	client *redundantdns.Client
	solver *Solver
	zone   *redundantdns.Zone
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	fake := rdnstest.NewFake(t)
	client, err := redundantdns.New(redundantdns.WithBaseURL(fake.URL), redundantdns.WithToken(rdnstest.DefaultToken))
	if err != nil {
		t.Fatal(err)
	}
	zone, err := client.Zones.Create(context.Background(), redundantdns.ZoneCreate{Name: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	kube := kubefake.NewClientset(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rdns-acme", Namespace: testNamespace},
		Data:       map[string][]byte{"token": []byte(rdnstest.DefaultToken + "\n")},
	}, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "rdns-revoked", Namespace: testNamespace},
		Data:       map[string][]byte{"token": []byte(revokedToken)},
	})
	solver := New(WithKubeClient(kube), WithPollInterval(time.Millisecond))
	if err := solver.Initialize(nil, nil); err != nil {
		t.Fatal(err)
	}
	return &harness{fake: fake, client: client, solver: solver, zone: zone}
}

func (h *harness) challenge(t *testing.T, fqdn, key string, extra map[string]any) *whapi.ChallengeRequest {
	t.Helper()
	config := map[string]any{"apiUrl": h.fake.URL, "tokenSecretRef": map[string]string{"name": "rdns-acme", "key": "token"}}
	for name, value := range extra {
		config[name] = value
	}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return &whapi.ChallengeRequest{
		ResourceNamespace: testNamespace, ResolvedFQDN: fqdn, ResolvedZone: "example.com.",
		DNSName: "example.com", Key: key, Config: &apiextensionsv1.JSON{Raw: raw},
	}
}

func TestSolverName(t *testing.T) {
	if New().Name() != "redundantdns" {
		t.Error("solver name must be redundantdns")
	}
}

func TestPresentWaitsAndCleansUp(t *testing.T) {
	h := newHarness(t)
	h.fake.SetACMEPropagation(3)
	challenge := h.challenge(t, "_acme-challenge.example.com.", testKey, nil)

	if err := h.solver.Present(challenge); err != nil {
		t.Fatal(err)
	}
	if values := h.fake.ACMEValues("_acme-challenge.example.com."); !slices.Equal(values, []string{testKey}) {
		t.Errorf("served = %v", values)
	}
	polls := 0
	for _, request := range h.fake.Requests() {
		if request.Pattern == "GET /v1/zones/{zoneId}/acme/challenges/{challengeId}" {
			polls++
		}
		if !strings.Contains(request.Path, "/acme/") {
			continue // the harness's own setup calls
		}
		if request.Header.Get("Authorization") != "Bearer "+rdnstest.DefaultToken {
			t.Errorf("%s %s without the token (trimmed from the Secret)", request.Method, request.Path)
		}
		if !strings.HasPrefix(request.Header.Get("User-Agent"), "redundantdns-cert-manager-webhook/") {
			t.Errorf("user agent = %q", request.Header.Get("User-Agent"))
		}
	}
	if polls != 4 {
		t.Errorf("status polls = %d, want 4 (3 pending, then propagated)", polls)
	}

	// Present again (cert-manager retries): idempotent.
	if err := h.solver.Present(challenge); err != nil {
		t.Fatal(err)
	}
	if len(h.fake.ACMEChallenges()) != 1 {
		t.Errorf("challenges = %+v", h.fake.ACMEChallenges())
	}

	if err := h.solver.CleanUp(challenge); err != nil {
		t.Fatal(err)
	}
	if len(h.fake.ACMEChallenges()) != 0 {
		t.Errorf("challenges after clean-up = %+v", h.fake.ACMEChallenges())
	}
	// Idempotent.
	if err := h.solver.CleanUp(challenge); err != nil {
		t.Errorf("second clean-up: %v", err)
	}
}

func TestApexAndWildcardKeepEachOther(t *testing.T) {
	h := newHarness(t)
	apex := h.challenge(t, "_acme-challenge.example.com.", testKey, nil)
	wildcard := h.challenge(t, "_acme-challenge.example.com.", "anothertestingkey", nil)
	for _, challenge := range []*whapi.ChallengeRequest{apex, wildcard} {
		if err := h.solver.Present(challenge); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.solver.CleanUp(wildcard); err != nil {
		t.Fatal(err)
	}
	if values := h.fake.ACMEValues("_acme-challenge.example.com."); !slices.Equal(values, []string{testKey}) {
		t.Errorf("served after one clean-up = %v", values)
	}
}

func TestPresentFailedState(t *testing.T) {
	h := newHarness(t)
	h.fake.FailACMEChallenges("verify-mode attachment in the NS plan")
	err := h.solver.Present(h.challenge(t, "_acme-challenge.www.example.com.", testKey, nil))
	if err == nil || !strings.Contains(err.Error(), "failed: verify-mode attachment in the NS plan") {
		t.Errorf("err = %v", err)
	}
}

func TestPresentTimeout(t *testing.T) {
	h := newHarness(t)
	h.fake.SetACMEPropagation(1_000_000)
	start := time.Now()
	err := h.solver.Present(h.challenge(t, "_acme-challenge.www.example.com.", testKey, map[string]any{"propagationTimeout": "100ms"}))
	if err == nil || !strings.Contains(err.Error(), "not propagated to every provider after 100ms") || !strings.Contains(err.Error(), "pending") {
		t.Errorf("err = %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Errorf("timeout took %s", elapsed)
	}
	// The value stays presented: the next Present continues the wait.
	if len(h.fake.ACMEChallenges()) != 1 {
		t.Errorf("challenges = %+v", h.fake.ACMEChallenges())
	}
}

func TestZoneResolutionAndConfiguredZone(t *testing.T) {
	h := newHarness(t)
	sub, err := h.client.Zones.Create(context.Background(), redundantdns.ZoneCreate{Name: "api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	challenge := h.challenge(t, "_acme-challenge.v1.api.example.com.", testKey, nil)
	challenge.ResolvedZone = "api.example.com."
	if err := h.solver.Present(challenge); err != nil {
		t.Fatal(err)
	}
	if infos := h.fake.ACMEChallenges(); len(infos) != 1 || infos[0].ZoneID != sub.ZoneID || infos[0].Name != "_acme-challenge.v1" {
		t.Errorf("challenges = %+v", infos)
	}

	// zoneId in the config skips the lookup.
	configured := h.challenge(t, "_acme-challenge.v2.api.example.com.", testKey, map[string]any{"zoneId": h.zone.ZoneID})
	before := len(h.fake.Requests())
	if err := h.solver.Present(configured); err != nil {
		t.Fatal(err)
	}
	for _, request := range h.fake.Requests()[before:] {
		if request.Path == "/v1/acme/zones" {
			t.Error("zoneId set: the zone list must not be read")
		}
	}
	if values := h.fake.ACMEValues("_acme-challenge.v2.api.example.com."); len(values) != 1 {
		t.Errorf("values = %v", values)
	}
}

func TestPresentErrorsExplainTheFix(t *testing.T) {
	h := newHarness(t)
	other, err := h.client.Zones.Create(context.Background(), redundantdns.ZoneCreate{Name: "example.org"})
	if err != nil {
		t.Fatal(err)
	}
	h.fake.RestrictACMEZones(h.zone.ZoneID)

	err = h.solver.Present(h.challenge(t, "_acme-challenge.example.org.", testKey, map[string]any{"zoneId": other.ZoneID}))
	if !redundantdns.HasCode(err, redundantdns.CodeZoneNotAllowed) || !strings.Contains(err.Error(), "not bound to this zone") {
		t.Errorf("zone not allowed: %v", err)
	}
	err = h.solver.Present(h.challenge(t, "_acme-challenge.example.org.", testKey, nil))
	if err == nil || !strings.Contains(err.Error(), "no zone of the token holds") {
		t.Errorf("no zone: %v", err)
	}
	// Clean-up of a name no zone holds: nothing to do.
	if err := h.solver.CleanUp(h.challenge(t, "_acme-challenge.example.org.", testKey, nil)); err != nil {
		t.Errorf("clean-up without a zone: %v", err)
	}
}

func TestCleanUpToleratesAGoneZone(t *testing.T) {
	h := newHarness(t)
	challenge := h.challenge(t, "_acme-challenge.example.com.", testKey, map[string]any{"zoneId": "zone-deleted"})
	if err := h.solver.CleanUp(challenge); err != nil {
		t.Errorf("clean-up in a deleted zone: %v", err)
	}
}

func TestTokenSecretErrors(t *testing.T) {
	h := newHarness(t)
	cases := map[string]struct {
		ref  map[string]string
		want string
	}{
		"missing secret": {map[string]string{"name": "nope"}, "read token secret cert-manager/nope"},
		"missing key":    {map[string]string{"name": "rdns-acme", "key": "other"}, `has no key "other"`},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := h.solver.Present(h.challenge(t, "_acme-challenge.example.com.", testKey, map[string]any{"tokenSecretRef": tc.ref}))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v", err)
			}
		})
	}
	if err := New().Present(h.challenge(t, "_acme-challenge.example.com.", testKey, nil)); err == nil || !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("uninitialized: %v", err)
	}
	// The token never shows up in an error.
	err := h.solver.Present(h.challenge(t, "_acme-challenge.example.com.", testKey, map[string]any{"tokenSecretRef": map[string]string{"name": "rdns-revoked"}}))
	if err == nil || strings.Contains(err.Error(), revokedToken) || !strings.Contains(err.Error(), "invalid, revoked or expired") {
		t.Errorf("unauthorized: %v", err)
	}
}

func TestProviderSummary(t *testing.T) {
	served := true
	status := &redundantdns.ACMEChallengeStatus{Providers: []redundantdns.ACMEProviderStatus{
		{Provider: "route53", Label: "aws", Applied: true, Served: &served},
		{Provider: "oci", Applied: true, Role: redundantdns.ACMERoleStandby},
		{Provider: "selfhost", Skipped: redundantdns.ACMESkippedVerify},
		{Provider: "cloudflare", Error: "rate limited"},
		{Provider: "ns1"},
	}}
	want := "route53 aws=served, oci=applied (standby), selfhost=skipped:verify, cloudflare=error: rate limited, ns1=pending"
	if got := providerSummary(status); got != want {
		t.Errorf("summary = %q", got)
	}
	if providerSummary(nil) != "no providers" {
		t.Error("nil status")
	}
}
