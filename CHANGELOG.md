# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-10-23

### Added

- cert-manager ACME DNS-01 webhook solver `redundantdns` (cert-manager
  v1.21): presents the challenge in the canonical zone, waits until every
  provider serves it, cleans it up by name and value.
- Configuration: `apiUrl`, `org`, `zoneId` (or lookup among the token's
  zones), `tokenSecretRef`, `ttl`, `propagationTimeout`.
- Helm chart (`deploy/chart`): 2 replicas, non-root, read-only root file
  system, APIService with a serving certificate issued by cert-manager,
  RBAC limited to the named token Secrets, NetworkPolicy,
  PodDisruptionBudget.
- cert-manager conformance suite against the go-client fake (or a real
  deployment).

Tested with cert-manager v1.21.2 against RedundantDNS v0.1.43 (Route 53 and
OCI DNS attachments, Let's Encrypt staging, apex and wildcard names).

[Unreleased]: https://github.com/redundantdns/cert-manager-webhook/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/redundantdns/cert-manager-webhook/releases/tag/v0.1.0
