package stack

import (
	"context"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"net"
)

type Stack interface {
	Run()
	SetupResolve(r zcdns.LocalServer)
	DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error)
	DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error)
}
