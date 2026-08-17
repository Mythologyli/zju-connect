package tcptunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/mythologyli/zju-connect/resolve"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if resolve.TCPPrefersL3(ctx) {
		return nil, fmt.Errorf("resource requires L3 tunnel, but TCP-only mode is active")
	}
	if s.client.CanUseTCPTunnel() {
		return s.client.DialTCP(ctx, addr)
	}

	return nil, fmt.Errorf("not implemented")
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
