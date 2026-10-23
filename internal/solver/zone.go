package solver

import (
	"errors"
	"fmt"
	"strings"

	redundantdns "github.com/redundantdns/go-client"
)

// errNoZone: none of the token's zones holds the challenge name.
var errNoZone = errors.New("no zone of the token holds the challenge name")

// resolvedZone is the zone a challenge goes to.
type resolvedZone struct {
	ZoneID string
	// Name is empty when the zone id came from the config.
	Name string
}

// label names the zone in messages.
func (zone resolvedZone) label() string {
	if zone.Name == "" {
		return zone.ZoneID
	}
	return zone.Name + " (" + zone.ZoneID + ")"
}

// resolveZone picks, among the token's zones, the one that holds fqdn:
// the zone cert-manager resolved as authoritative (resolvedZone, found by
// SOA lookup) when the token has it, else the longest zone name fqdn ends
// with. Names compare case-insensitively, trailing dots ignored.
func resolveZone(zones []redundantdns.ACMEZone, fqdn, resolvedZoneName string) (resolvedZone, error) {
	name := canonical(fqdn)
	authoritative := canonical(resolvedZoneName)
	var best *redundantdns.ACMEZone
	for index := range zones {
		zone := &zones[index]
		zoneName := canonical(zone.Name)
		if zoneName == "" || (name != zoneName && !strings.HasSuffix(name, "."+zoneName)) {
			continue
		}
		if zoneName == authoritative {
			return resolvedZone{ZoneID: zone.ZoneID, Name: zoneName}, nil
		}
		if best == nil || len(zoneName) > len(canonical(best.Name)) {
			best = zone
		}
	}
	if best == nil {
		names := make([]string, 0, len(zones))
		for _, zone := range zones {
			names = append(names, zone.Name)
		}
		return resolvedZone{}, fmt.Errorf("%w: %s (resolved zone %s; the token's zones: %s; set zoneId or bind the token to the zone)",
			errNoZone, name, authoritative, strings.Join(names, ", "))
	}
	return resolvedZone{ZoneID: best.ZoneID, Name: canonical(best.Name)}, nil
}

// canonical lowercases a DNS name and drops the trailing dot.
func canonical(name string) string {
	return strings.TrimRight(strings.ToLower(strings.TrimSpace(name)), ".")
}
