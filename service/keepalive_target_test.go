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
		input       string
		wantURLs    []string
		wantWarning int
	}{
		{
			name:     "a plain http application inside the vpn",
			input:    "http://10.0.0.1/",
			wantURLs: []string{"http://10.0.0.1/"},
		},
		{
			name:        "https is reached with CONNECT and does not count as application traffic",
			input:       "https://www.cnki.net/favicon.ico",
			wantURLs:    []string{"https://www.cnki.net/favicon.ico"},
			wantWarning: 1,
		},
		{
			name:        "a value that is not a url is dropped",
			input:       "10.0.0.1",
			wantURLs:    nil,
			wantWarning: 1,
		},
		{
			name:     "the comma-separated form is trimmed and deduplicated",
			input:    " http://10.0.0.1/ , ,http://10.0.0.1/,http://10.0.0.2/",
			wantURLs: []string{"http://10.0.0.1/", "http://10.0.0.2/"},
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
			name:      "a grant covering port 80 is probed on port 80",
			resources: []client.IPResource{httpResource("10.0.0.1", "", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.1/"},
		},
		{
			name:      "a range is probed at its first address and says so",
			resources: []client.IPResource{httpResource("10.0.0.0", "10.255.255.255", 80, 80, "tcp")},
			wantURLs:  []string{"http://10.0.0.0/"},
			wantNotes: true,
		},
		{
			name:      "a grant for port 22 is not an HTTP application",
			resources: []client.IPResource{httpResource("10.0.0.7", "", 22, 22, "tcp")},
			wantURLs:  nil,
			wantNotes: true,
		},
		{
			name:      "a grant for port 443 is not probed with plain HTTP",
			resources: []client.IPResource{httpResource("10.0.0.7", "", 443, 443, "tcp")},
			wantURLs:  nil,
			wantNotes: true,
		},
		{
			name:      "a non-standard single port is not probed",
			resources: []client.IPResource{httpResource("10.0.0.55", "", 8080, 8080, "tcp")},
			wantURLs:  nil,
			wantNotes: true,
		},
		{
			name:      "a port-22 grant does not hide a later port-80 grant",
			resources: []client.IPResource{httpResource("10.0.0.7", "", 22, 22, "tcp"), httpResource("10.0.0.8", "", 80, 80, "tcp")},
			wantURLs:  []string{"http://10.0.0.8/"},
		},
		{
			name:      "an ipv6 destination proves nothing and is skipped",
			resources: []client.IPResource{httpResource("2001:db8::1", "", 80, 80, "all")},
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
		{
			name: "duplicate addresses are probed once",
			resources: []client.IPResource{
				httpResource("10.0.0.1", "", 80, 80, "tcp"),
				httpResource("10.0.0.1", "", 1, 65535, "all"),
			},
			wantURLs: []string{"http://10.0.0.1/"},
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
	addresses := make([]string, 0, maxDerivedCandidates+2)
	for i := range maxDerivedCandidates + 2 {
		address := net.IPv4(10, 0, 0, byte(i+1)).String()
		addresses = append(addresses, address)
		resources = append(resources, httpResource(address, "", 80, 80, "tcp"))
	}

	targets, _ := DeriveKeepAliveTargets(resources)
	if len(targets) != maxDerivedCandidates {
		t.Fatalf("targets = %d, want the %d-candidate bound", len(targets), maxDerivedCandidates)
	}
	for i, target := range targets {
		want := "http://" + addresses[i] + "/"
		if target.URL != want {
			t.Fatalf("target %d = %s, want %s (the resource order sets the order)", i, target.URL, want)
		}
	}
}
