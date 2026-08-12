package dial

import (
	"context"
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ippool"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/internal/zcdns"
	"github.com/mythologyli/zju-connect/resolve"
)

func TestMatchesIPResourcePreservesRangePortAndProtocolRules(t *testing.T) {
	resources := []client.IPResource{{
		IPMin:    net.IPv4(10, 0, 0, 1),
		IPMax:    net.IPv4(10, 0, 0, 10),
		PortMin:  443,
		PortMax:  443,
		Protocol: "tcp",
	}}
	index := ipresource.New(resources)

	tests := []struct {
		name    string
		ip      net.IP
		network string
		port    int
		want    bool
	}{
		{name: "match", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 443, want: true},
		{name: "outside range", ip: net.IPv4(10, 0, 0, 11), network: "tcp", port: 443},
		{name: "wrong port", ip: net.IPv4(10, 0, 0, 5), network: "tcp", port: 80},
		{name: "wrong protocol", ip: net.IPv4(10, 0, 0, 5), network: "udp", port: 443},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := matchesIPResource(index, test.ip, test.network, test.port); got != test.want {
				t.Fatalf("matchesIPResource() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestDialIPPortSelectsMatchingDomainResource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "https"},
		{PortMin: 80, PortMax: 80, Protocol: "tcp", AppID: "http"},
	}
	ctx := context.WithValue(context.Background(), resolve.ContextKeyDomainResource, resources)
	dialer := &Dialer{stack: &capturingStack{}, resourceIndex: ipresource.New(nil)}

	_, err := dialer.DialIPPort(ctx, "tcp", "121.194.4.13:443")
	if err != nil {
		t.Fatalf("DialIPPort() error = %v", err)
	}
	if got := dialer.stack.(*capturingStack).domainResource.AppID; got != "https" {
		t.Fatalf("selected AppID = %q, want https", got)
	}
}

type capturingStack struct {
	domainResource client.DomainResource
}

func (s *capturingStack) Run()                                                {}
func (s *capturingStack) SetupResolve(zcdns.LocalServer)                      {}
func (s *capturingStack) SetupIPPool(*ippool.IPPool[[]client.DomainResource]) {}
func (s *capturingStack) DialTCP(ctx context.Context, _ *net.TCPAddr) (net.Conn, error) {
	s.domainResource = ctx.Value(resolve.ContextKeyDomainResource).(client.DomainResource)
	return nil, nil
}
func (s *capturingStack) DialUDP(context.Context, *net.UDPAddr) (net.Conn, error) {
	return nil, nil
}
