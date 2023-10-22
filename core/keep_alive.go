package core

import (
	"context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"log"
	"net"
	"time"
)

func KeepAlive(dnsServer string, ipStack *stack.Stack, selfIp []byte) {
	var remoteResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			addrDns := tcpip.FullAddress{
				NIC:  defaultNIC,
				Port: uint16(53),
				Addr: tcpip.AddrFromSlice(net.ParseIP(dnsServer).To4()),
			}

			bind := tcpip.FullAddress{
				NIC:  defaultNIC,
				Addr: tcpip.AddrFromSlice(selfIp),
			}

			return gonet.DialUDP(ipStack, &bind, &addrDns, header.IPv4ProtocolNumber)
		},
	}

	for {
		_, err := remoteResolver.LookupIP(context.Background(), "ip4", "www.baidu.com")
		if err != nil {
			log.Printf("KeepAlive: %s", err)
		} else {
			log.Printf("KeepAlive: OK")
		}

		time.Sleep(60 * time.Second)
	}
}
