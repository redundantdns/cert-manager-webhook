// Package dnstest runs a tiny authoritative DNS server for tests: it
// answers TXT questions from a lookup function (for example the values the
// go-client fake holds) so cert-manager's conformance suite can check that
// a presented challenge resolves.
package dnstest

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Lookup returns the TXT values at an absolute name (lowercase, trailing
// dot); none answers NXDOMAIN.
type Lookup func(fqdn string) []string

// Server is a running test DNS server (UDP and TCP on the same port).
type Server struct {
	// Addr is host:port, for example 127.0.0.1:53535.
	Addr string

	servers []*dns.Server
	once    sync.Once
}

// Start serves lookup on 127.0.0.1 at a free port.
func Start(lookup Lookup) (*Server, error) {
	handler := dns.HandlerFunc(func(writer dns.ResponseWriter, request *dns.Msg) {
		answer := new(dns.Msg)
		answer.SetReply(request)
		answer.Authoritative = true
		if len(request.Question) == 1 {
			question := request.Question[0]
			values := lookup(strings.ToLower(question.Name))
			switch {
			case len(values) == 0:
				answer.Rcode = dns.RcodeNameError
			case question.Qtype == dns.TypeTXT:
				for _, value := range values {
					answer.Answer = append(answer.Answer, &dns.TXT{
						Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 0},
						Txt: []string{value},
					})
				}
			}
		}
		_ = writer.WriteMsg(answer)
	})
	// A free UDP port, then TCP on the same one (retry when another process
	// holds the TCP side).
	for attempt := 0; attempt < 20; attempt++ {
		packetConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			return nil, fmt.Errorf("dnstest: listen udp: %w", err)
		}
		addr := packetConn.LocalAddr().String()
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			_ = packetConn.Close()
			continue
		}
		server := &Server{Addr: addr}
		started := make(chan error, 2)
		notify := func() { started <- nil }
		server.servers = []*dns.Server{
			{PacketConn: packetConn, Handler: handler, NotifyStartedFunc: notify},
			{Listener: listener, Handler: handler, NotifyStartedFunc: notify},
		}
		for _, dnsServer := range server.servers {
			go func(dnsServer *dns.Server) {
				if err := dnsServer.ActivateAndServe(); err != nil {
					started <- err
				}
			}(dnsServer)
		}
		for range server.servers {
			select {
			case err := <-started:
				if err != nil {
					server.Close()
					return nil, fmt.Errorf("dnstest: serve: %w", err)
				}
			case <-time.After(5 * time.Second):
				server.Close()
				return nil, fmt.Errorf("dnstest: server did not start")
			}
		}
		return server, nil
	}
	return nil, fmt.Errorf("dnstest: no free port for UDP and TCP")
}

// Close stops the server.
func (server *Server) Close() {
	server.once.Do(func() {
		for _, dnsServer := range server.servers {
			_ = dnsServer.Shutdown()
		}
	})
}
