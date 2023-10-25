package service

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

type DNSServer struct {
	resolver *resolve.Resolver
}

func (d DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	switch r.Opcode {
	case dns.OpcodeQuery:
		for _, q := range r.Question {
			name := q.Name
			if len(name) > 1 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}

			switch q.Qtype {
			case dns.TypeA:
				if _, ip, err := d.resolver.Resolve(context.Background(), name); err == nil {
					if ip.To4() != nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
						if err == nil {
							m.Answer = append(m.Answer, rr)
						}
					}
				}
			case dns.TypeAAAA:
				if _, ip, err := d.resolver.Resolve(context.Background(), name); err == nil {
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

func ServeDNS(bindAddr string, resolver *resolve.Resolver) {
	dnsServer := &DNSServer{resolver: resolver}
	dns.HandleFunc(".", dnsServer.handleDNSRequest)

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
