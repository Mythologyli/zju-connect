package atrust

import (
	"net"
	"testing"

	"github.com/mythologyli/zju-connect/internal/ipresource"
)

func TestParseResourceIncludesIPv6Addresses(t *testing.T) {
	client := NewClient("", "", "", "")
	resource := []byte(`{
		"data":{"appList":{"data":{"appInfo":[{"apps":[{
			"id":"ipv6-app","nodeGroupID":"group","addressList":[
				{"protocol":"tcp","port":"443","host":"2001:db8::/64"},
				{"protocol":"tcp","port":"443","host":"vpn.example","ip":["2001:db8::53","2001:db8::54"]}
			]
		}]}]}}}
	}`)
	if err := client.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	matched, ok := ipresource.New(client.ipResources).Match(net.ParseIP("2001:db8::42"), "tcp", 443)
	if !ok || matched.AppID != "ipv6-app" {
		t.Fatalf("IPv6 resource match = %+v, %v", matched, ok)
	}
	if got := client.dnsResource["vpn.example"]; len(got) != 2 || !got[0].Equal(net.ParseIP("2001:db8::53")) || !got[1].Equal(net.ParseIP("2001:db8::54")) {
		t.Fatalf("IPv6 DNS resource = %v", got)
	}
}

func TestParseResourceKeepsPolicyDNSServers(t *testing.T) {
	client := NewClient("", "", "", "")
	resource := []byte(`{
		"data":{"sdpPolicy":{"data":{"clientOption":{"dnsOption":{
			"firstDNS":"10.0.0.53","secondDNS":"10.0.0.54"
		}}}}}
	}`)
	if err := client.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	servers, err := client.DNSServers()
	if err != nil {
		t.Fatalf("DNSServers() error = %v", err)
	}
	if len(servers) != 2 || servers[0] != "10.0.0.53" || servers[1] != "10.0.0.54" {
		t.Fatalf("DNS servers = %v", servers)
	}
}
