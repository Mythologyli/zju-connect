package tcptunnel

import (
	"context"
	"fmt"
	"net"

	"github.com/mythologyli/zju-connect/resolve"
)

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if s.client.CanUseTCPTunnel() {
		return s.client.DialTCP(resolve.WithIgnoreTCPPrefL3(ctx), addr)
	}

	return nil, fmt.Errorf("not implemented")
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
