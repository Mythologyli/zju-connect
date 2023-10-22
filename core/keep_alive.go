package core

import (
	"context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"log"
	"net"
	"time"
)

func KeepAlive(dnsServer string, client *EasyConnectClient) {
	var remoteResolver net.Resolver

	if TunMode {
		remoteResolver = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				addrDns := net.UDPAddr{
					IP:   net.ParseIP(dnsServer),
					Port: 53,
				}

				bind := net.UDPAddr{
					IP:   net.IP(client.clientIp),
					Port: 0,
				}

				return net.DialUDP(network, &bind, &addrDns)
			},
		}
	} else {
		remoteResolver = net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				addrDns := tcpip.FullAddress{
					NIC:  defaultNIC,
					Port: uint16(53),
					Addr: tcpip.AddrFromSlice(net.ParseIP(dnsServer).To4()),
				}

				bind := tcpip.FullAddress{
					NIC:  defaultNIC,
					Addr: tcpip.AddrFromSlice(client.clientIp),
				}

				return gonet.DialUDP(client.gvisorStack, &bind, &addrDns, header.IPv4ProtocolNumber)
			},
		}
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
