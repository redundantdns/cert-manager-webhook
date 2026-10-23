package solver

import (
	"strings"
	"testing"
	"time"

	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

func rawConfig(text string) *apiextensionsv1.JSON {
	return &apiextensionsv1.JSON{Raw: []byte(text)}
}

func TestLoadConfigDefaults(t *testing.T) {
	config, err := loadConfig(rawConfig(`{"tokenSecretRef":{"name":"rdns-acme"}}`), configDefaults{})
	if err != nil {
		t.Fatal(err)
	}
	if config.APIURL != "https://app.redundantdns.com" || config.TTL != DefaultTTL ||
		config.PropagationTimeout.Duration != DefaultPropagationTimeout || config.TokenSecretRef != (SecretKeySelector{Name: "rdns-acme", Key: "token"}) {
		t.Errorf("config = %+v", config)
	}

	config, err = loadConfig(rawConfig(`{"tokenSecretRef":{"name":"rdns-acme"}}`), configDefaults{apiURL: "https://dns.internal.example"})
	if err != nil || config.APIURL != "https://dns.internal.example" {
		t.Errorf("chart default: %+v, %v", config, err)
	}
}

func TestLoadConfigFull(t *testing.T) {
	config, err := loadConfig(rawConfig(`{
		"apiUrl": " https://rdns.example.com/ ", "org": "org-1", "zoneId": "zon-1",
		"tokenSecretRef": {"name": "acme", "key": "pat"}, "ttl": 120, "propagationTimeout": "3m"
	}`), configDefaults{apiURL: "https://ignored.example"})
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		APIURL: "https://rdns.example.com/", Org: "org-1", ZoneID: "zon-1",
		TokenSecretRef: SecretKeySelector{Name: "acme", Key: "pat"}, TTL: 120, PropagationTimeout: Duration{3 * time.Minute},
	}
	if config != want {
		t.Errorf("config = %+v, want %+v", config, want)
	}
	config, err = loadConfig(rawConfig(`{"tokenSecretRef":{"name":"a"},"propagationTimeout":90}`), configDefaults{})
	if err != nil || config.PropagationTimeout.Duration != 90*time.Second {
		t.Errorf("seconds: %+v, %v", config.PropagationTimeout, err)
	}
}

func TestLoadConfigRefusals(t *testing.T) {
	cases := map[string]struct {
		raw      *apiextensionsv1.JSON
		defaults configDefaults
		want     string
	}{
		"nil":            {nil, configDefaults{}, "missing webhook config"},
		"empty":          {rawConfig(" "), configDefaults{}, "missing webhook config"},
		"no secret":      {rawConfig(`{"apiUrl":"https://a.example"}`), configDefaults{}, "tokenSecretRef.name is required"},
		"typo":           {rawConfig(`{"tokenSecretRef":{"name":"a"},"zone":"zon-1"}`), configDefaults{}, `unknown field "zone"`},
		"not json":       {rawConfig(`apiUrl: x`), configDefaults{}, "decode webhook config"},
		"http":           {rawConfig(`{"apiUrl":"http://rdns.example.com","tokenSecretRef":{"name":"a"}}`), configDefaults{}, "must use https"},
		"ftp":            {rawConfig(`{"apiUrl":"ftp://rdns.example.com","tokenSecretRef":{"name":"a"}}`), configDefaults{}, "must use https"},
		"relative":       {rawConfig(`{"apiUrl":"rdns.example.com","tokenSecretRef":{"name":"a"}}`), configDefaults{}, "not an absolute URL"},
		"ttl":            {rawConfig(`{"tokenSecretRef":{"name":"a"},"ttl":-1}`), configDefaults{}, "ttl -1 out of range"},
		"timeout":        {rawConfig(`{"tokenSecretRef":{"name":"a"},"propagationTimeout":"1h"}`), configDefaults{}, "out of range"},
		"timeout syntax": {rawConfig(`{"tokenSecretRef":{"name":"a"},"propagationTimeout":"soon"}`), configDefaults{}, "propagationTimeout"},
		"timeout type":   {rawConfig(`{"tokenSecretRef":{"name":"a"},"propagationTimeout":true}`), configDefaults{}, "duration string"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := loadConfig(tc.raw, tc.defaults)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadConfigInsecureURLs(t *testing.T) {
	for _, apiURL := range []string{"http://127.0.0.1:8080", "http://localhost:8080", "http://[::1]:8080"} {
		if _, err := loadConfig(rawConfig(`{"apiUrl":"`+apiURL+`","tokenSecretRef":{"name":"a"}}`), configDefaults{}); err != nil {
			t.Errorf("%s: %v", apiURL, err)
		}
	}
	if _, err := loadConfig(rawConfig(`{"apiUrl":"http://rdns.lab:8080","tokenSecretRef":{"name":"a"}}`), configDefaults{allowInsecure: true}); err != nil {
		t.Errorf("allowed insecure: %v", err)
	}
}

func TestDurationJSON(t *testing.T) {
	encoded, err := Duration{90 * time.Second}.MarshalJSON()
	if err != nil || string(encoded) != `"1m30s"` {
		t.Errorf("marshal = %s, %v", encoded, err)
	}
	var duration Duration
	if err := duration.UnmarshalJSON([]byte("null")); err != nil || duration.Duration != 0 {
		t.Errorf("null = %v, %v", duration, err)
	}
}
