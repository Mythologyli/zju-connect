package tun

import (
	"context"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.endpoint.client.CanUseTCPTunnel() {
		return s.endpoint.client.DialTCP(ctx, addr)
	}

	return net.DialTCP("tcp4", &net.TCPAddr{
		IP:   s.endpoint.ip,
		Port: 0,
	}, addr)
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return net.DialUDP("udp4", &net.UDPAddr{
		IP:   s.endpoint.ip,
		Port: 0,
	}, addr)
}
