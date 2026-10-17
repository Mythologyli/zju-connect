package service

import (
	"fmt"
	"net"
	"net/netip"
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
		routes    []string
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
		{
			name:   "the routes the tunnel installed are probed before the granted resources",
			routes: []string{"10.0.0.55/32", "10.0.0.1/32"},
			resources: []client.IPResource{
				httpResource("10.0.0.1", "", 1, 65535, "all"),
				httpResource("10.0.0.55", "", 8080, 8080, "tcp"),
			},
			wantURLs:  []string{"http://10.0.0.55:8080/", "http://10.0.0.1/"},
			wantNotes: true,
		},
		{
			name:      "a route to an address the account was not granted is refused",
			routes:    []string{"10.0.0.9/32"},
			resources: []client.IPResource{httpResource("10.0.0.1", "", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.1/"},
			wantNotes: true,
		},
		{
			name:      "a route that covers a range names no single address",
			routes:    []string{"10.0.0.0/24"},
			resources: []client.IPResource{httpResource("10.0.0.10", "", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.10/"},
			wantNotes: true,
		},
		{
			name:      "an ipv6 route names no address to probe",
			routes:    []string{"2001:db8::1/128"},
			resources: []client.IPResource{httpResource("10.0.0.1", "", 1, 65535, "all")},
			wantURLs:  []string{"http://10.0.0.1/"},
			wantNotes: true,
		},
		{
			name:      "a route already granted as a resource target is probed once",
			routes:    []string{"10.0.0.10/32"},
			resources: []client.IPResource{httpResource("10.0.0.10", "", 1, 65535, "tcp")},
			wantURLs:  []string{"http://10.0.0.10/"},
			wantNotes: true,
		},
		{
			name:      "a route granted without a plain HTTP port is not probed on port 80",
			routes:    []string{"10.0.0.7/32"},
			resources: []client.IPResource{httpResource("10.0.0.7", "", 22, 22, "tcp")},
			wantURLs:  []string{"http://10.0.0.7:22/"},
			wantNotes: true,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			targets, notes := DeriveKeepAliveTargets(parsePrefixes(tt.routes), tt.resources)
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

func parsePrefixes(values []string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			panic(fmt.Sprintf("test wrote the invalid prefix %q", value))
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func TestDeriveKeepAliveTargetsIsBounded(t *testing.T) {
	resources := make([]client.IPResource, 0, maxDerivedCandidates+2)
	routes := make([]netip.Prefix, 0, maxDerivedCandidates+2)
	addresses := make([]string, 0, maxDerivedCandidates+2)
	for i := range maxDerivedCandidates + 2 {
		address := net.IPv4(10, 0, 0, byte(i+1)).String()
		addresses = append(addresses, address)
		resources = append(resources, httpResource(address, "", 1, 65535, "all"))
		routes = append(routes, netip.MustParsePrefix(address+"/32"))
	}

	targets, _ := DeriveKeepAliveTargets(routes, resources)
	if len(targets) != maxDerivedCandidates {
		t.Fatalf("targets = %d, want the %d-candidate bound", len(targets), maxDerivedCandidates)
	}
	for i, target := range targets {
		want := "http://" + addresses[i] + "/"
		if target.URL != want {
			t.Fatalf("target %d = %s, want %s (the routes set the order)", i, target.URL, want)
		}
	}
}
