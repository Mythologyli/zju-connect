package service

import (
	"context"
	"fmt"
	"github.com/miekg/dns"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"net"
)

type DNSServer struct {
	resolver *resolve.Resolver
	localDNS []net.IP
}

func (d DNSServer) serveDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false

	_ = d.handleSingleDNSResolve(context.Background(), r, m)

	_ = w.WriteMsg(m)
}

func (d DNSServer) HandleDnsMsg(ctx context.Context, requestMsg *dns.Msg) (*dns.Msg, error) {
	resMsg := new(dns.Msg)
	resMsg.SetReply(requestMsg)
	resMsg.Compress = false

	err := d.handleSingleDNSResolve(ctx, requestMsg, resMsg)
	return resMsg, err
}

func (d DNSServer) CheckDnsHijack(dstIP net.IP) bool {
	for _, ip := range d.localDNS {
		if ip.Equal(dstIP) {
			return false
		}
	}
	return true
}

func (d DNSServer) handleSingleDNSResolve(ctx context.Context, requestMsg *dns.Msg, resMsg *dns.Msg) error {
	switch requestMsg.Opcode {
	case dns.OpcodeQuery:
		for _, q := range requestMsg.Question {
			name := q.Name
			if len(name) > 1 && name[len(name)-1] == '.' {
				name = name[:len(name)-1]
			}

			switch q.Qtype {
			case dns.TypeA:
				if _, ip, err := d.resolver.Resolve(ctx, name); err == nil {
					if ip.To4() != nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s A %s", q.Name, ip))
						if err == nil {
							resMsg.Answer = append(resMsg.Answer, rr)
						}
					}
				}
			case dns.TypeAAAA:
				if _, ip, err := d.resolver.Resolve(ctx, name); err == nil {
					if ip.To4() == nil {
						rr, err := dns.NewRR(fmt.Sprintf("%s AAAA %s", q.Name, ip))
						if err == nil {
							resMsg.Answer = append(resMsg.Answer, rr)
						}
					}
				}
			}
		}
	}
	return nil
}

func NewDnsServer(resolver *resolve.Resolver, dnsServers []string) DNSServer {
	netIPs := make([]net.IP, len(dnsServers))
	for _, dnsServer := range dnsServers {
		if net.ParseIP(dnsServer) != nil {
			netIPs = append(netIPs, net.ParseIP(dnsServer))
		}
	}
	return DNSServer{resolver: resolver, localDNS: netIPs}
}

func ServeDNS(bindAddr string, dnsServer DNSServer) {
	dns.HandleFunc(".", dnsServer.serveDNSRequest)

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
