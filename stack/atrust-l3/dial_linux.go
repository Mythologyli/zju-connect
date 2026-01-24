//go:build !android

package atrustl3

import (
	"context"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	return s.endpoint.tcpDialer.DialContext(ctx, "tcp4", addr.String())
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return s.endpoint.udpDialer.DialContext(ctx, "udp4", addr.String())
}
