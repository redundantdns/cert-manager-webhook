package solver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	redundantdns "github.com/redundantdns/go-client"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
)

// Defaults of the solver configuration.
const (
	DefaultTTL                = 60
	DefaultPropagationTimeout = 120 * time.Second
	DefaultTokenSecretKey     = "token"

	// maxTTL bounds the challenge TTL (one day): a challenge lives minutes.
	maxTTL = 86400
	// maxPropagationTimeout bounds the wait of one Present call; a longer
	// wait gains nothing because cert-manager retries Present.
	maxPropagationTimeout = 10 * time.Minute
)

// Config is the solver configuration of an Issuer or ClusterIssuer
// (spec.acme.solvers[].dns01.webhook.config).
type Config struct {
	// APIURL is the RedundantDNS deployment (default
	// https://app.redundantdns.com, or the chart's apiUrl value).
	APIURL string `json:"apiUrl"`
	// Org is optional: a token is bound to one organization.
	Org string `json:"org"`
	// ZoneID skips the zone lookup (GET /v1/acme/zones).
	ZoneID string `json:"zoneId"`
	// TokenSecretRef names the Secret (in the Issuer's namespace, or the
	// cert-manager namespace for a ClusterIssuer) holding the token.
	TokenSecretRef SecretKeySelector `json:"tokenSecretRef"`
	// TTL of the challenge TXT value in seconds (default 60).
	TTL int `json:"ttl"`
	// PropagationTimeout bounds how long Present waits for every provider
	// to serve the value (default 120s).
	PropagationTimeout Duration `json:"propagationTimeout"`
}

// SecretKeySelector points at one key of a Secret.
type SecretKeySelector struct {
	Name string `json:"name"`
	// Key defaults to "token".
	Key string `json:"key"`
}

// Duration is a time.Duration written as a Go duration string ("120s",
// "2m") or a number of seconds.
type Duration struct{ time.Duration }

// UnmarshalJSON accepts "90s" or 90.
func (duration *Duration) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}
	var text string
	if err := json.Unmarshal(data, &text); err == nil {
		parsed, err := time.ParseDuration(strings.TrimSpace(text))
		if err != nil {
			return fmt.Errorf("propagationTimeout %q: %w", text, err)
		}
		duration.Duration = parsed
		return nil
	}
	var seconds float64
	if err := json.Unmarshal(data, &seconds); err != nil {
		return fmt.Errorf("propagationTimeout must be a duration string (\"120s\") or a number of seconds: %s", data)
	}
	duration.Duration = time.Duration(seconds * float64(time.Second))
	return nil
}

// MarshalJSON writes the Go duration string.
func (duration Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(duration.String())
}

// configDefaults are the deployment-wide settings a Config falls back to.
type configDefaults struct {
	apiURL string
	// allowInsecure accepts http:// API URLs on non-loopback hosts (tests
	// and lab installs only).
	allowInsecure bool
}

// loadConfig decodes and validates a challenge's configuration, filling
// in the defaults. Unknown fields are refused so a typo does not silently
// fall back to a default.
func loadConfig(raw *apiextensionsv1.JSON, defaults configDefaults) (Config, error) {
	var config Config
	if raw == nil || len(bytes.TrimSpace(raw.Raw)) == 0 {
		return config, errors.New("missing webhook config: set at least tokenSecretRef")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw.Raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return config, fmt.Errorf("decode webhook config: %w", err)
	}
	config.APIURL = strings.TrimSpace(config.APIURL)
	if config.APIURL == "" {
		config.APIURL = defaults.apiURL
	}
	if config.APIURL == "" {
		config.APIURL = redundantdns.DefaultBaseURL
	}
	if err := checkAPIURL(config.APIURL, defaults.allowInsecure); err != nil {
		return config, err
	}
	config.Org = strings.TrimSpace(config.Org)
	config.ZoneID = strings.TrimSpace(config.ZoneID)
	config.TokenSecretRef.Name = strings.TrimSpace(config.TokenSecretRef.Name)
	config.TokenSecretRef.Key = strings.TrimSpace(config.TokenSecretRef.Key)
	if config.TokenSecretRef.Name == "" {
		return config, errors.New("webhook config: tokenSecretRef.name is required")
	}
	if config.TokenSecretRef.Key == "" {
		config.TokenSecretRef.Key = DefaultTokenSecretKey
	}
	switch {
	case config.TTL == 0:
		config.TTL = DefaultTTL
	case config.TTL < 0 || config.TTL > maxTTL:
		return config, fmt.Errorf("webhook config: ttl %d out of range (1..%d)", config.TTL, maxTTL)
	}
	switch {
	case config.PropagationTimeout.Duration == 0:
		config.PropagationTimeout.Duration = DefaultPropagationTimeout
	case config.PropagationTimeout.Duration < 0 || config.PropagationTimeout.Duration > maxPropagationTimeout:
		return config, fmt.Errorf("webhook config: propagationTimeout %s out of range (up to %s)", config.PropagationTimeout, maxPropagationTimeout)
	}
	return config, nil
}

// checkAPIURL refuses a malformed URL, and a plain http URL unless the host
// is a loopback address or insecure URLs are allowed: the token travels in
// the Authorization header.
func checkAPIURL(rawURL string, allowInsecure bool) error {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Host == "" {
		return fmt.Errorf("webhook config: apiUrl %q is not an absolute URL", rawURL)
	}
	switch parsed.Scheme {
	case "https":
		return nil
	case "http":
		if allowInsecure || isLoopback(parsed.Hostname()) {
			return nil
		}
		return fmt.Errorf("webhook config: apiUrl %q must use https (the token would travel in clear text)", rawURL)
	}
	return fmt.Errorf("webhook config: apiUrl %q must use https", rawURL)
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
