package solver

import (
	"errors"
	"strings"
	"testing"

	redundantdns "github.com/redundantdns/go-client"
)

func TestResolveZone(t *testing.T) {
	zones := []redundantdns.ACMEZone{
		{ZoneID: "zon-com", Name: "example.com"},
		{ZoneID: "zon-sub", Name: "api.example.com"},
		{ZoneID: "zon-other", Name: "other-example.com"},
	}
	cases := []struct {
		name, fqdn, resolvedZone, want string
	}{
		{"apex", "_acme-challenge.example.com.", "example.com.", "zon-com"},
		{"case and dots", "_ACME-challenge.WWW.Example.COM", "EXAMPLE.com", "zon-com"},
		{"longest suffix", "_acme-challenge.v1.api.example.com.", "", "zon-sub"},
		// The SOA lookup found example.com authoritative (the subzone is
		// not delegated publicly): follow cert-manager.
		{"authoritative wins", "_acme-challenge.v1.api.example.com.", "example.com.", "zon-com"},
		// A resolved zone the token does not have: longest match.
		{"unknown resolved zone", "_acme-challenge.v1.api.example.com.", "v1.api.example.com.", "zon-sub"},
		// A label boundary: other-example.com is not under example.com.
		{"label boundary", "_acme-challenge.other-example.com.", "other-example.com.", "zon-other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			zone, err := resolveZone(zones, tc.fqdn, tc.resolvedZone)
			if err != nil || zone.ZoneID != tc.want {
				t.Errorf("zone = %+v, %v; want %s", zone, err, tc.want)
			}
		})
	}
}

func TestResolveZoneNone(t *testing.T) {
	_, err := resolveZone([]redundantdns.ACMEZone{{ZoneID: "zon-1", Name: "example.com"}}, "_acme-challenge.example.org.", "example.org.")
	if !errors.Is(err, errNoZone) || !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "zoneId") {
		t.Errorf("err = %v", err)
	}
	if _, err := resolveZone(nil, "_acme-challenge.example.org.", ""); !errors.Is(err, errNoZone) {
		t.Errorf("no zones: %v", err)
	}
}
