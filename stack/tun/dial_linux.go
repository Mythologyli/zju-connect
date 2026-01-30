package tun

import (
	"context"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return s.endpoint.udpDialer.Dial("udp4", addr.String())
}
