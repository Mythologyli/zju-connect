package tun

import (
	"context"
	"net"

	"github.com/mythologyli/zju-connect/resolve"
	"inet.af/netaddr"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() && !resolve.TCPPrefersL3(ctx) {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	s.endpoint.configMu.RLock()
	defer s.endpoint.configMu.RUnlock()
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
	}
	return net.DialTCP("tcp4", nil, addr)
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	s.endpoint.configMu.RLock()
	defer s.endpoint.configMu.RUnlock()
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.udpDialer.Dial("udp4", addr.String())
	}
	return net.DialUDP("udp4", nil, addr)
}
