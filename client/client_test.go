package client

import "testing"

func TestMatchDomainResourceSelectsPortAndProtocol(t *testing.T) {
	resources := []DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "https"},
		{PortMin: 80, PortMax: 80, Protocol: "all", AppID: "http"},
	}

	tests := []struct {
		name    string
		network string
		port    int
		wantID  string
	}{
		{name: "https", network: "tcp", port: 443, wantID: "https"},
		{name: "all protocol", network: "udp", port: 80, wantID: "http"},
		{name: "wrong port", network: "tcp", port: 22},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resource, ok := MatchDomainResource(resources, test.network, test.port)
			if ok != (test.wantID != "") || resource.AppID != test.wantID {
				t.Fatalf("MatchDomainResource() = (%#v, %v), want AppID %q", resource, ok, test.wantID)
			}
		})
	}
}

func TestMatchDomainResourceIgnoresPortForICMP(t *testing.T) {
	resource, ok := MatchDomainResource([]DomainResource{{Protocol: "icmp", AppID: "ping"}}, "icmp", -1)
	if !ok || resource.AppID != "ping" {
		t.Fatalf("MatchDomainResource() = (%#v, %v), want ICMP match", resource, ok)
	}
}
