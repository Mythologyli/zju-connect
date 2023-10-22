package core

import (
	"context"
	"fmt"
	"log"
)
import "github.com/miekg/dns"

type DnsServer struct {
	dnsResolve *DnsResolve
}

func (dnsServer DnsServer) handleDnsRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range r.Question {
			switch q.Qtype {
			case dns.TypeA:
				if _, ip, err := dnsServer.dnsResolve.Resolve(context.Background(), q.Name); err == nil {
					if ip.To4() != nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
						if err == nil {
							m.Answer = append(m.Answer, rr)
						}
					}
				}
			case dns.TypeAAAA:
				if _, ip, err := dnsServer.dnsResolve.Resolve(context.Background(), q.Name); err == nil {
					if ip.To4() == nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
						if err == nil {
							m.Answer = append(m.Answer, rr)
						}
					}
				}
			}
		}
	}

	_ = w.WriteMsg(m)
}

func ServeDns(bindAddr string, dnsResolve *DnsResolve) {
	log.Printf("DNS server listening on " + bindAddr)

	dnsServer := &DnsServer{dnsResolve: dnsResolve}
	dns.HandleFunc(".", dnsServer.handleDnsRequest)

	server := &dns.Server{Addr: bindAddr, Net: "udp"}
	log.Printf("Starting DNS server at %s", server.Addr)

	err := server.ListenAndServe()
	if err != nil {
		log.Printf("Failed to start DNS server: %s", err.Error())
	}

	defer func(server *dns.Server) {
		_ = server.Shutdown()
	}(server)
}
