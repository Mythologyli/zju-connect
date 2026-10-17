package service

import (
	"net"
	"slices"
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func httpResource(ipMin, ipMax string, portMin, portMax int, protocol string) client.IPResource {
	resource := client.IPResource{
		IPMin:    net.ParseIP(ipMin),
		PortMin:  portMin,
		PortMax:  portMax,
		Protocol: protocol,
	}
	if ipMax != "" {
		resource.IPMax = net.ParseIP(ipMax)
	}
	return resource
}

func TestNamedKeepAliveTargets(t *testing.T) {
	for _, tt := range []struct {
		name        string
		input       []string
		wantURLs    []string
		wantWarning int
	}{
		{
			name:     "a plain http application inside the vpn",
			input:    []string{"http://10.0.0.1/"},
			wantURLs: []string{"http://10.0.0.1/"},
		},
		{
			name:        "https is reached with CONNECT and does not count as application traffic",
			input:       []string{"https://www.cnki.net/favicon.ico"},
			wantURLs:    []string{"https://www.cnki.net/favicon.ico"},
			wantWarning: 1,
		},
		{
			name:        "a value that is not a url is dropped",
			input:       []string{"10.0.0.1"},
			wantURLs:    nil,
			wantWarning: 1,
		},
		{
			name:     "whitespace is trimmed, duplicates are probed once",
			input:    []string{" http://10.0.0.1/ ", "", "http://10.0.0.1/"},
			wantURLs: []string{"http://10.0.0.1/"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets, warnings := NamedKeepAliveTargets(tt.input)
			if len(warnings) != tt.wantWarning {
				t.Fatalf("warnings = %v, want %d", warnings, tt.wantWarning)
			}
			if got := urls(targets); !slices.Equal(got, tt.wantURLs) {
				t.Fatalf("targets = %v, want %v", got, tt.wantURLs)
			}
			for _, target := range targets {
				if !target.Named {
					t.Fatalf("target %s is not marked as named", target.URL)
				}
			}
		})
	}
}

func TestDeriveKeepAliveTargets(t *testing.T) {
	for _, tt := range []struct {
		name      string
		resources []client.IPResource
		wantURLs  []string
		wantNotes bool
	}{
		{
			name:      "a host granted every port is probed on port 80",
			resources: []client.IPResource{httpResource("10.0.0.1", "", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.1/"},
		},
		{
			name:      "a single non-standard port is probed on that port",
			resources: []client.IPResource{httpResource("10.0.0.55", "", 8080, 8080, "tcp")},
			wantURLs:  []string{"http://10.0.0.55:8080/"},
		},
		{
			name:      "a range is probed at its first address and says so",
			resources: []client.IPResource{httpResource("10.0.0.0", "10.255.255.255", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.0/"},
			wantNotes: true,
		},
		{
			name:      "an ipv6 destination proves nothing and is skipped",
			resources: []client.IPResource{httpResource("2001:db8::1", "", 1, 65535, "all")},
			wantURLs:  nil,
			wantNotes: true,
		},
		{
			name:      "a udp-only resource carries no http",
			resources: []client.IPResource{httpResource("10.0.0.1", "", 53, 53, "udp")},
			wantURLs:  nil,
			wantNotes: true,
		},
		{
			name:      "no resource at all is reported, not guessed",
			resources: nil,
			wantURLs:  nil,
			wantNotes: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets, notes := DeriveKeepAliveTargets(tt.resources)
			if got := urls(targets); !slices.Equal(got, tt.wantURLs) {
				t.Fatalf("targets = %v, want %v (notes: %v)", got, tt.wantURLs, notes)
			}
			if tt.wantNotes && len(notes) == 0 {
				t.Fatal("no note was produced")
			}
			if !tt.wantNotes && len(notes) != 0 {
				t.Fatalf("unexpected notes: %v", notes)
			}
			for _, target := range targets {
				if target.Named {
					t.Fatalf("derived target %s is marked as named", target.URL)
				}
			}
		})
	}
}

func TestDeriveKeepAliveTargetsIsBounded(t *testing.T) {
	resources := make([]client.IPResource, 0, maxDerivedCandidates+2)
	for i := range maxDerivedCandidates + 2 {
		resources = append(resources, httpResource(
			net.IPv4(10, 0, byte(i), 1).String(), "", 1, 65535, "all"))
	}

	targets, _ := DeriveKeepAliveTargets(resources)
	if len(targets) != maxDerivedCandidates {
		t.Fatalf("targets = %d, want the %d-candidate bound", len(targets), maxDerivedCandidates)
	}
}
