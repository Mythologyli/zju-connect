package tun

import (
	"context"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	s.endpoint.configMu.RLock()
	defer s.endpoint.configMu.RUnlock()
	return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	s.endpoint.configMu.RLock()
	defer s.endpoint.configMu.RUnlock()
	return s.endpoint.udpDialer.Dial("udp4", addr.String())
}
