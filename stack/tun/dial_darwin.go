package tun

import (
	"context"
	"inet.af/netaddr"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
	}
	return net.DialTCP("tcp4", nil, addr)
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.udpDialer.Dial("udp4", addr.String())
	}
	return net.DialUDP("udp4", nil, addr)
}
