// Command cert-manager-webhook is the cert-manager ACME DNS-01 webhook
// solver for RedundantDNS. It runs the aggregated API server cert-manager
// calls (solver name "redundantdns") under the group name in GROUP_NAME
// (default acme.redundantdns.com).
package main

import (
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"

	"github.com/redundantdns/cert-manager-webhook/internal/solver"
)

// DefaultGroupName is the API group used when GROUP_NAME is unset. An
// Issuer's dns01.webhook.groupName must match it.
const DefaultGroupName = "acme.redundantdns.com"

// groupName returns GROUP_NAME or the default.
func groupName() string {
	if name := strings.TrimSpace(os.Getenv("GROUP_NAME")); name != "" {
		return name
	}
	return DefaultGroupName
}

func main() {
	cmd.RunWebhookServer(groupName(), solver.New())
}
