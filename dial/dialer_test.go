package dial

import (
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
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
