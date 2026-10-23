//go:build conformance

// The cert-manager DNS01 webhook conformance suite (test/acme), as the
// upstream webhook-example runs it. It needs the envtest binaries
// (TEST_ASSET_ETCD, TEST_ASSET_KUBE_APISERVER, TEST_ASSET_KUBECTL) and is
// behind the "conformance" build tag because cert-manager's test package
// panics at init when they are missing. Run it with `make test-conformance`.
//
// Two modes:
//
//   - Fake (default): the go-client fake API plus an in-process DNS server
//     answering the TXT values the fake holds.
//   - Platform: RDNS_API_URL and RDNS_TOKEN point at a real deployment (for
//     example `RDNS_E2E=1 ./bin/rdns all-in-one`) with the zone
//     TEST_ZONE_NAME; RDNS_DNS_SERVER (host:port) is the nameserver to check
//     (default: follow the authoritative nameservers from 8.8.8.8);
//     RDNS_ZONE_ID skips the zone lookup.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	acmetest "github.com/cert-manager/cert-manager/test/acme"
	redundantdns "github.com/redundantdns/go-client"
	"github.com/redundantdns/go-client/rdnstest"

	"github.com/redundantdns/cert-manager-webhook/internal/dnstest"
	"github.com/redundantdns/cert-manager-webhook/internal/solver"
)

// conformanceKey is a realistic challenge value: the API accepts base64url
// only, so the suite's default ("123d==") would be refused.
const conformanceKey = "LoqXcYV8q5ONbJQxbmR7SCTNo3tiAXDfowyjxAjEuX0"

func TestConformance(t *testing.T) {
	zone := os.Getenv("TEST_ZONE_NAME")
	if zone == "" {
		t.Skip("TEST_ZONE_NAME is not set (for example example.com.)")
	}
	for _, key := range []string{"TEST_ASSET_ETCD", "TEST_ASSET_KUBE_APISERVER", "TEST_ASSET_KUBECTL"} {
		if os.Getenv(key) == "" {
			t.Skipf("%s is not set: run make test-conformance", key)
		}
	}
	if !strings.HasSuffix(zone, ".") {
		zone += "."
	}

	manifests := t.TempDir()
	config := map[string]any{"tokenSecretRef": map[string]string{"name": "rdns-acme", "key": "token"}, "propagationTimeout": "60s"}
	options := []acmetest.Option{
		acmetest.SetResolvedZone(zone),
		// The API accepts _acme-challenge names only; the suite's default
		// (cert-manager-dns01-tests.<zone>) would be refused.
		acmetest.SetResolvedFQDN("_acme-challenge.cert-manager-dns01-tests." + zone),
		acmetest.SetAllowAmbientCredentials(false),
		acmetest.SetManifestPath(manifests),
		acmetest.SetStrict(true),
		acmetest.SetDNSChallengeKey(conformanceKey),
		acmetest.SetPollInterval(time.Second),
		acmetest.SetPropagationLimit(2 * time.Minute),
	}
	var token string
	if apiURL := os.Getenv("RDNS_API_URL"); apiURL != "" {
		token = os.Getenv("RDNS_TOKEN")
		if token == "" {
			t.Fatal("RDNS_API_URL is set without RDNS_TOKEN")
		}
		config["apiUrl"] = apiURL
		if zoneID := os.Getenv("RDNS_ZONE_ID"); zoneID != "" {
			config["zoneId"] = zoneID
		}
		if server := os.Getenv("RDNS_DNS_SERVER"); server != "" {
			options = append(options, acmetest.SetDNSServer(server), acmetest.SetUseAuthoritative(false))
		}
		t.Logf("platform mode: %s", apiURL)
	} else {
		fake := rdnstest.NewFake(t)
		token = fake.Token
		client, err := redundantdns.New(redundantdns.WithBaseURL(fake.URL), redundantdns.WithToken(token))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.Zones.Create(context.Background(), redundantdns.ZoneCreate{Name: zone}); err != nil {
			t.Fatal(err)
		}
		fake.SetACMEPropagation(2)
		server, err := dnstest.Start(fake.ACMEValues)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(server.Close)
		config["apiUrl"] = fake.URL
		options = append(options, acmetest.SetDNSServer(server.Addr), acmetest.SetUseAuthoritative(false))
		t.Logf("fake mode: API %s, DNS %s", fake.URL, server.Addr)
	}

	writeJSON(t, filepath.Join(manifests, "config.json"), config)
	// The suite applies every manifest of the directory in each test
	// namespace: the token Secret the config points at. The directory is
	// t.TempDir(), removed when the test ends.
	writeJSON(t, filepath.Join(manifests, "secret.json"), map[string]any{
		"apiVersion": "v1", "kind": "Secret",
		"metadata":   map[string]string{"name": "rdns-acme"},
		"stringData": map[string]string{"token": token},
	})

	webhook := solver.New(solver.WithPollInterval(500*time.Millisecond), solver.WithInsecureAPIURL(true))
	acmetest.NewFixture(webhook, options...).RunConformance(t)
}

func writeJSON(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(fmt.Errorf("write %s: %w", path, err))
	}
}
