package atrustl3

import (
	"context"
	"net"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	return net.DialTCP("tcp4", nil, addr)
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return net.DialUDP("udp4", nil, addr)
}
