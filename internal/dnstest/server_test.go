package dnstest

import (
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestServerAnswersTXT(t *testing.T) {
	server, err := Start(func(fqdn string) []string {
		if fqdn == "_acme-challenge.example.com." {
			return []string{"one", "two"}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network}
		question := new(dns.Msg)
		question.SetQuestion("_ACME-challenge.example.com.", dns.TypeTXT)
		answer, _, err := client.Exchange(question, server.Addr)
		if err != nil {
			t.Fatalf("%s: %v", network, err)
		}
		var values []string
		for _, record := range answer.Answer {
			values = append(values, record.(*dns.TXT).Txt...)
		}
		if answer.Rcode != dns.RcodeSuccess || !answer.Authoritative || !slices.Equal(values, []string{"one", "two"}) {
			t.Errorf("%s answer = %v", network, answer)
		}

		question.SetQuestion("_acme-challenge.example.com.", dns.TypeCNAME)
		if answer, _, err = client.Exchange(question, server.Addr); err != nil || answer.Rcode != dns.RcodeSuccess || len(answer.Answer) != 0 {
			t.Errorf("%s CNAME answer = %v, %v", network, answer, err)
		}
		question.SetQuestion("missing.example.com.", dns.TypeTXT)
		if answer, _, err = client.Exchange(question, server.Addr); err != nil || answer.Rcode != dns.RcodeNameError {
			t.Errorf("%s missing answer = %v, %v", network, answer, err)
		}
	}
}
