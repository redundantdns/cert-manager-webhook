# RedundantDNS webhook for cert-manager

A [cert-manager](https://cert-manager.io) ACME DNS-01 solver for zones
managed by [RedundantDNS](https://redundantdns.com). It lets a Kubernetes
cluster obtain certificates, wildcards included, for any RedundantDNS zone
with a token that can do nothing but create and delete `_acme-challenge`
TXT values in the zones it was given.

## Why a dedicated solver

A RedundantDNS zone is replicated to two or more DNS providers (Route 53,
OCI DNS, Cloudflare...), and the registrar delegates to all of their
nameservers. A provider's own cert-manager solver writes the TXT value at
that provider only, so the CA's validators, which may ask any delegated
nameserver, fail at random.

This webhook writes the challenge into the canonical zone, which fans it
out to every provider, and then **waits until every provider serves the
value**: the platform checks that each attachment applied the zone serial
and that every one of its nameservers answers the TXT authoritatively. Only
then does `Present` return and cert-manager ask the CA to validate.
cert-manager's own self-check still runs afterwards, against the public
resolution path.

## Install

You need cert-manager in the cluster (built and tested against v1.21).

1. **Token.** In the dashboard, API tokens, Create token, token type
   "cert-manager (ACME DNS-01)": pick the zones, and optionally restrict it
   to the cluster's egress IPs. ACME DNS-01 is available on every plan
   (RedundantDNS v0.1.43 and later). Copy the token (`rdns_...`, shown once).
   The token has the `acme:challenge` scope only: it cannot read or change
   any other record.

2. **Secret** in the cert-manager namespace (for a ClusterIssuer) or the
   Issuer's namespace:

   ```sh
   kubectl -n cert-manager create secret generic rdns-acme --from-literal=token=rdns_...
   ```

3. **Webhook:**

   ```sh
   helm install rdns-webhook oci://ghcr.io/redundantdns/charts/cert-manager-webhook \
     --namespace cert-manager --version 0.1.0
   ```

   The webhook may read only the Secrets listed in `secretNames` (default
   `rdns-acme`) in `secretNamespaces` (default: the release namespace).

4. **Issuer.** A ClusterIssuer for Let's Encrypt:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-rdns
   spec:
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: ops@example.com
       privateKeySecretRef:
         name: letsencrypt-rdns-account
       solvers:
         - dns01:
             webhook:
               groupName: acme.redundantdns.com
               solverName: redundantdns
               config:
                 tokenSecretRef:
                   name: rdns-acme
                   key: token
           selector:
             dnsZones: ["example.com"]
   ```

   A namespaced Issuer is the same with `kind: Issuer`; its token Secret
   lives in the Issuer's namespace, which must then be in the chart's
   `secretNamespaces`:

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Issuer
   metadata:
     name: letsencrypt-rdns
     namespace: shop
   spec:
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: ops@example.com
       privateKeySecretRef:
         name: letsencrypt-rdns-account
       solvers:
         - dns01:
             webhook:
               groupName: acme.redundantdns.com
               solverName: redundantdns
               config:
                 zoneId: zon-...
                 tokenSecretRef:
                   name: rdns-acme
                   key: token
                 propagationTimeout: 3m
   ```

5. **Certificate** for the apex and the wildcard (two challenge values at
   the same name, both kept):

   ```yaml
   apiVersion: cert-manager.io/v1
   kind: Certificate
   metadata:
     name: example-com
     namespace: shop
   spec:
     secretName: example-com-tls
     issuerRef:
       name: letsencrypt-rdns
       kind: ClusterIssuer
     dnsNames:
       - example.com
       - "*.example.com"
   ```

## Configuration

`dns01.webhook.config`:

| Field | Default | Meaning |
|---|---|---|
| `tokenSecretRef.name` | (required) | Secret holding the token, in the Issuer's namespace (ClusterIssuer: cert-manager's cluster resource namespace) |
| `tokenSecretRef.key` | `token` | Key of the Secret |
| `apiUrl` | chart `apiUrl`, else `https://app.redundantdns.com` | RedundantDNS deployment; self-hosted installs change it. `https` only (plain `http` is accepted for loopback addresses, or everywhere with `RDNS_ALLOW_INSECURE_API_URL=true` for labs) |
| `org` | | Organization id; optional, a token is bound to one organization |
| `zoneId` | resolved | Skips the zone lookup. Without it the webhook lists the token's zones (`GET /v1/acme/zones`) and picks the one cert-manager resolved as authoritative, else the longest zone name the challenge name ends with |
| `ttl` | `60` | TTL of the challenge TXT value, seconds |
| `propagationTimeout` | `120s` | How long one `Present` call waits for every provider (Go duration or seconds, up to 10m). On timeout `Present` fails and cert-manager calls it again; presenting is idempotent, so the wait simply continues |

Unknown fields are refused, so a typo does not silently fall back to a
default.

Chart values (`deploy/chart/values.yaml`): `groupName` (default
`acme.redundantdns.com`, must match the Issuers' `groupName`), `apiUrl`,
`image.repository` / `image.tag` / `image.digest`, `certManager.namespace`
and `certManager.serviceAccountName` (allowed to call the webhook),
`secretNames`, `secretNamespaces`, `replicaCount` (2), `resources`,
`networkPolicy.*`, `podDisruptionBudget.*`, `nodeSelector`, `tolerations`,
`affinity`, `topologySpreadConstraints`, `logLevel`.

## CNAME delegation

A common pattern points `_acme-challenge.app.example.com` at a name in
another zone with a CNAME (for example a zone dedicated to challenges).
Present refuses a name that holds a CNAME (`409 cnameConflict`): set
`cnameStrategy: Follow` on the Certificate (or Issuer), so cert-manager
follows the CNAME and the webhook presents the value in the target zone,
which the token must then be bound to.

## Troubleshooting

- `kubectl describe challenge <name>` shows the webhook's error, which
  names the challenge id, the state and each provider
  (`route53 aws=served, oci=applied (standby)`).
- The webhook logs every challenge id and state change (never the token):
  `kubectl -n cert-manager logs deploy/rdns-webhook-cert-manager-webhook`.
- The platform's view of a challenge:
  `GET /v1/zones/{zoneId}/acme/challenges/{challengeId}` with the token
  shows, per provider, whether the serial was applied and what each
  nameserver answered.
- `failed` comes back at once with the reason (a provider rejected the
  change, a verify-mode attachment is still in the NS plan...). `pending`
  past `propagationTimeout` is retried by cert-manager.
- `403 zoneNotAllowed`: the token is not bound to that zone. `401`: the
  token is invalid, revoked or expired. `409 zoneMirrored`: a mirrored zone
  takes no writes; use the source provider's solver.
- Rate limits: at most 50 live challenges per zone and about 300 presents
  per zone per hour (`429 tooManyChallenges`), on top of the per-token API
  rate. Many certificates at once are fine; a crash loop is not.

## Security

- The token's scope `acme:challenge` reaches only the challenge routes,
  and only for its zones; it cannot list or change other records.
- Restrict it further with an IP allowlist (the cluster's egress
  addresses) when you create it.
- Revoke it in the dashboard at any time; the webhook reads the Secret on
  every call, so a rotated token is picked up without a restart.
- The webhook's ServiceAccount can `get` only the Secrets named in
  `secretNames`, in `secretNamespaces`. The pods run as non-root on a
  read-only root filesystem with every capability dropped, and the
  NetworkPolicy allows egress only to DNS, the API port and the
  Kubernetes API.
- The token is never logged and never part of an error message.

## Development

```sh
make vet          # go vet, also with the conformance build tag
make test         # unit tests (go-client fake, fake Kubernetes API)
make lint         # golangci-lint v2.14.0
make vuln         # govulncheck v1.8.0
make helm-lint    # helm v4.3.0 lint --strict and template

# cert-manager's DNS01 conformance suite (downloads the pinned envtest
# control plane): against the go-client fake and an in-process DNS server
make test-conformance
# or against a deployment, for example `RDNS_E2E=1 ./bin/rdns all-in-one`
# with the zone example.com and its fake DNS responder:
RDNS_API_URL=http://localhost:8080 RDNS_TOKEN=rdns_... \
  RDNS_DNS_SERVER=127.0.0.1:5353 TEST_ZONE_NAME=example.com. make test-conformance
```

The conformance test is behind the `conformance` build tag because
cert-manager's test package panics at init without the envtest binaries.

## Releasing

Update `CHANGELOG.md` and push a `vX.Y.Z` tag: the release workflow pushes
the multi-arch image (`ghcr.io/redundantdns/cert-manager-webhook`, with
provenance and an SBOM) and the chart, with the image digest pinned, to
`oci://ghcr.io/redundantdns/charts/cert-manager-webhook`. Before a tag,
`make check test-conformance` and, for changes to the API calls, the
conformance suite against a RedundantDNS deployment (see Development).

## License

Apache License 2.0, see [LICENSE](LICENSE) and [NOTICE](NOTICE).
