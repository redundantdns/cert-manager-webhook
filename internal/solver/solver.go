// Package solver implements the cert-manager ACME DNS-01 webhook solver for
// RedundantDNS: it presents the challenge value in the canonical zone,
// waits until every provider the zone is replicated to serves it, and
// removes it afterwards.
package solver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook"
	whapi "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	redundantdns "github.com/redundantdns/go-client"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// Name is the solver name an Issuer refers to (dns01.webhook.solverName).
const Name = "redundantdns"

// Version is the webhook version, set at build time
// (-ldflags "-X .../internal/solver.Version=v1.2.3"). It goes into the
// User-Agent of API calls.
var Version = "dev"

// Environment variables read by New.
const (
	// EnvDefaultAPIURL is the API URL used when a config has no apiUrl (the
	// chart's apiUrl value).
	EnvDefaultAPIURL = "RDNS_DEFAULT_API_URL"
	// EnvAllowInsecureAPIURL ("true") accepts http:// API URLs on
	// non-loopback hosts. For lab installs only.
	EnvAllowInsecureAPIURL = "RDNS_ALLOW_INSECURE_API_URL"
)

// apiCallTimeout bounds one API call (the client also retries 429 and 5xx
// within it).
const apiCallTimeout = 30 * time.Second

// cleanUpTimeout bounds a whole CleanUp call.
const cleanUpTimeout = 60 * time.Second

// Solver is the RedundantDNS webhook.Solver.
type Solver struct {
	kube kubernetes.Interface
	// kubeInjected: the client came from WithKubeClient and Initialize
	// keeps it.
	kubeInjected bool
	defaults     configDefaults
	pollInterval time.Duration
	httpClient   *http.Client
}

var _ webhook.Solver = (*Solver)(nil)

// Option configures a Solver (tests).
type Option func(solver *Solver)

// WithKubeClient sets the Kubernetes client instead of building one in
// Initialize.
func WithKubeClient(client kubernetes.Interface) Option {
	return func(solver *Solver) { solver.kube, solver.kubeInjected = client, true }
}

// WithPollInterval changes the status poll interval (default 2 s).
func WithPollInterval(interval time.Duration) Option {
	return func(solver *Solver) { solver.pollInterval = interval }
}

// WithDefaultAPIURL sets the API URL used when a config has none.
func WithDefaultAPIURL(apiURL string) Option {
	return func(solver *Solver) { solver.defaults.apiURL = apiURL }
}

// WithInsecureAPIURL accepts http:// API URLs on any host.
func WithInsecureAPIURL(allow bool) Option {
	return func(solver *Solver) { solver.defaults.allowInsecure = allow }
}

// New builds a Solver configured from the environment (EnvDefaultAPIURL,
// EnvAllowInsecureAPIURL), then from the options.
func New(options ...Option) *Solver {
	solver := &Solver{
		defaults: configDefaults{
			apiURL:        strings.TrimSpace(os.Getenv(EnvDefaultAPIURL)),
			allowInsecure: strings.EqualFold(strings.TrimSpace(os.Getenv(EnvAllowInsecureAPIURL)), "true"),
		},
		pollInterval: redundantdns.DefaultACMEPollInterval,
		httpClient:   &http.Client{Timeout: apiCallTimeout},
	}
	for _, option := range options {
		option(solver)
	}
	return solver
}

// Name implements webhook.Solver.
func (solver *Solver) Name() string { return Name }

// Initialize implements webhook.Solver: it builds the Kubernetes client
// used to read the token Secrets (unless one was given). A second call
// replaces the client (the conformance suite starts a new control plane per
// group of tests).
func (solver *Solver) Initialize(kubeClientConfig *restclient.Config, _ <-chan struct{}) error {
	if solver.kubeInjected {
		return nil
	}
	client, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return fmt.Errorf("build kubernetes client: %w", err)
	}
	solver.kube = client
	return nil
}

// Present implements webhook.Solver: it presents the challenge value, then
// polls its propagation until every provider serves it. A timeout is an
// error: cert-manager calls Present again, which is idempotent, and the
// wait goes on.
func (solver *Solver) Present(challenge *whapi.ChallengeRequest) error {
	config, err := loadConfig(challenge.Config, solver.defaults)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), config.PropagationTimeout.Duration+apiCallTimeout)
	defer cancel()
	client, err := solver.client(ctx, challenge.ResourceNamespace, config)
	if err != nil {
		return err
	}
	zone, err := solver.zone(ctx, client, config, challenge)
	if err != nil {
		return err
	}
	presented, err := client.ACME.Present(ctx, zone.ZoneID, redundantdns.ACMEChallengeInput{
		Name: challenge.ResolvedFQDN, Value: challenge.Key, TTL: config.TTL,
	})
	if err != nil {
		return fmt.Errorf("present %s in zone %s: %w", challenge.ResolvedFQDN, zone.label(), explain(err))
	}
	klog.InfoS("challenge presented", "challengeId", presented.ChallengeID, "fqdn", presented.FQDN,
		"zoneId", zone.ZoneID, "serial", presented.Serial, "existing", presented.Existing, "dnsName", challenge.DNSName)

	waitCtx, cancelWait := context.WithTimeout(ctx, config.PropagationTimeout.Duration)
	defer cancelWait()
	lastState := ""
	status, err := client.ACME.WaitPropagated(waitCtx, zone.ZoneID, presented.ChallengeID, redundantdns.ACMEWaitOptions{
		Interval: solver.pollInterval,
		OnStatus: func(status *redundantdns.ACMEChallengeStatus) {
			// Log state changes only: a poll every 2 s would flood the log.
			if status.State != lastState {
				lastState = status.State
				klog.InfoS("challenge propagation", "challengeId", status.ChallengeID, "state", status.State,
					"serial", status.Serial, "providers", providerSummary(status))
			}
		},
	})
	switch {
	case err == nil:
		return nil
	case errors.Is(err, redundantdns.ErrACMEChallengeFailed):
		return fmt.Errorf("challenge %s for %s failed: %s (%s)", presented.ChallengeID, presented.FQDN, status.Reason, providerSummary(status))
	case waitCtx.Err() != nil:
		summary := "no status read"
		if status != nil {
			summary = status.State + ", " + providerSummary(status)
		}
		return fmt.Errorf("challenge %s for %s not propagated to every provider after %s (%s); cert-manager retries",
			presented.ChallengeID, presented.FQDN, config.PropagationTimeout, summary)
	}
	return fmt.Errorf("challenge %s status: %w", presented.ChallengeID, explain(err))
}

// CleanUp implements webhook.Solver: it removes the challenge value by
// name and value. A value, challenge or zone already gone is success.
func (solver *Solver) CleanUp(challenge *whapi.ChallengeRequest) error {
	config, err := loadConfig(challenge.Config, solver.defaults)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cleanUpTimeout)
	defer cancel()
	client, err := solver.client(ctx, challenge.ResourceNamespace, config)
	if err != nil {
		return err
	}
	zone, err := solver.zone(ctx, client, config, challenge)
	if errors.Is(err, errNoZone) {
		// The token no longer addresses a zone holding the name: there is
		// nothing this solver could remove.
		klog.InfoS("challenge clean-up skipped: no zone", "fqdn", challenge.ResolvedFQDN, "reason", err.Error())
		return nil
	}
	if err != nil {
		return err
	}
	err = client.ACME.CleanUpValue(ctx, zone.ZoneID, challenge.ResolvedFQDN, challenge.Key)
	if err != nil && !redundantdns.IsNotFound(err) {
		return fmt.Errorf("clean up %s in zone %s: %w", challenge.ResolvedFQDN, zone.label(), explain(err))
	}
	klog.InfoS("challenge cleaned up", "fqdn", challenge.ResolvedFQDN, "zoneId", zone.ZoneID)
	return nil
}

// client reads the token Secret and builds an API client. The token is
// never logged.
func (solver *Solver) client(ctx context.Context, namespace string, config Config) (*redundantdns.Client, error) {
	token, err := solver.token(ctx, namespace, config.TokenSecretRef)
	if err != nil {
		return nil, err
	}
	options := []redundantdns.Option{
		redundantdns.WithBaseURL(config.APIURL),
		redundantdns.WithToken(token),
		redundantdns.WithUserAgent("redundantdns-cert-manager-webhook/" + Version),
		redundantdns.WithHTTPClient(solver.httpClient),
	}
	if config.Org != "" {
		options = append(options, redundantdns.WithOrg(config.Org))
	}
	client, err := redundantdns.New(options...)
	if err != nil {
		return nil, fmt.Errorf("api client: %w", err)
	}
	return client, nil
}

// token reads the API token from the referenced Secret.
func (solver *Solver) token(ctx context.Context, namespace string, ref SecretKeySelector) (string, error) {
	if solver.kube == nil {
		return "", errors.New("solver not initialized: no kubernetes client")
	}
	secret, err := solver.kube.CoreV1().Secrets(namespace).Get(ctx, ref.Name, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("read token secret %s/%s (the chart's secretNames must list it): %w", namespace, ref.Name, err)
	}
	value, ok := secret.Data[ref.Key]
	if !ok {
		return "", fmt.Errorf("token secret %s/%s has no key %q", namespace, ref.Name, ref.Key)
	}
	token := strings.TrimSpace(string(value))
	if token == "" {
		return "", fmt.Errorf("token secret %s/%s: key %q is empty", namespace, ref.Name, ref.Key)
	}
	return token, nil
}

// zone returns the configured zone or resolves it from the token's zones.
func (solver *Solver) zone(ctx context.Context, client *redundantdns.Client, config Config, challenge *whapi.ChallengeRequest) (resolvedZone, error) {
	if config.ZoneID != "" {
		return resolvedZone{ZoneID: config.ZoneID}, nil
	}
	zones, err := client.ACME.Zones(ctx)
	if err != nil {
		return resolvedZone{}, fmt.Errorf("list the token's zones: %w", explain(err))
	}
	return resolveZone(zones, challenge.ResolvedFQDN, challenge.ResolvedZone)
}

// providerSummary renders the per-provider propagation for logs and
// errors, for example "route53 aws=served, oci prod=applied".
func providerSummary(status *redundantdns.ACMEChallengeStatus) string {
	if status == nil || len(status.Providers) == 0 {
		return "no providers"
	}
	parts := make([]string, 0, len(status.Providers))
	for _, provider := range status.Providers {
		label := provider.Provider
		if provider.Label != "" {
			label += " " + provider.Label
		}
		state := "pending"
		switch {
		case provider.Skipped != "":
			state = "skipped:" + provider.Skipped
		case provider.Error != "":
			state = "error: " + provider.Error
		case provider.Served != nil && *provider.Served:
			state = "served"
		case provider.Applied:
			state = "applied"
		}
		if provider.Role == redundantdns.ACMERoleStandby {
			state += " (standby)"
		}
		parts = append(parts, label+"="+state)
	}
	return strings.Join(parts, ", ")
}

// explain adds the operator's next step to the API errors a misconfigured
// install meets.
func explain(err error) error {
	switch {
	case redundantdns.HasCode(err, redundantdns.CodeZoneNotAllowed):
		return fmt.Errorf("%w (the token is not bound to this zone: add it to the token, or create one for it)", err)
	case redundantdns.HasCode(err, redundantdns.CodeInsufficientScope):
		return fmt.Errorf("%w (the token needs the acme:challenge scope)", err)
	case redundantdns.HasCode(err, redundantdns.CodeCnameConflict):
		return fmt.Errorf("%w (the name is a CNAME: set cnameStrategy: Follow on the Certificate or Issuer so the challenge goes to the target zone)", err)
	case redundantdns.HasCode(err, redundantdns.CodeZoneMirrored):
		return fmt.Errorf("%w (a mirrored zone takes no writes: use the source provider's solver)", err)
	case errors.Is(err, redundantdns.ErrUnauthorized):
		return fmt.Errorf("%w (the token is invalid, revoked or expired)", err)
	}
	return err
}
