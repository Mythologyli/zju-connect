package atrust

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
)

func TestParseResourcePreservesMultipleRulesForDomain(t *testing.T) {
	var policy ClientResource
	appInfo := struct{ Apps []resourceApp }{}
	for _, rule := range []struct{ id, group, port string }{
		{id: "https-app", group: "https-group", port: "443"},
		{id: "http-app", group: "http-group", port: "80"},
	} {
		var app resourceApp
		app.ID, app.NodeGroupID, app.AccessModel = rule.id, rule.group, "L3VPN"
		app.AddressList = append(app.AddressList, resourceAddress{Protocol: "tcp", Port: rule.port, Host: "www.cnki.net"})
		appInfo.Apps = append(appInfo.Apps, app)
	}
	policy.Data.AppList.Data.AppInfo = append(policy.Data.AppList.Data.AppInfo, appInfo)
	resource, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	c := &Client{}
	if err := c.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}

	rules := c.domainResources["www.cnki.net"]
	if len(rules) != 2 {
		t.Fatalf("domain rules = %#v, want 2 rules", rules)
	}
	if got, ok := client.MatchDomainResource(rules, "tcp", 443); !ok || got.AppID != "https-app" || got.NodeGroupID != "https-group" {
		t.Fatalf("443 rule = (%#v, %v), want https app metadata", got, ok)
	}
	if got, ok := client.MatchDomainResource(rules, "tcp", 80); !ok || got.AppID != "http-app" || got.NodeGroupID != "http-group" {
		t.Fatalf("80 rule = (%#v, %v), want http app metadata", got, ok)
	}
}

func TestParseResourceDoesNotOverrideTCPTunnelZeroRTT(t *testing.T) {
	c := &Client{tcpTunnelZeroRTT: true}
	policy := []byte(`{"data":{"sdpPolicy":{"data":{"clientOption":{"tun0rtt":{"enable":false}}}}}}`)
	if err := c.parseResource(policy); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	if !c.tcpTunnelZeroRTT {
		t.Fatal("SDP tunnel pool policy overrode the manifest zero-RTT capability")
	}
}

func TestParseResourceConfiguresTCPTunnelPool(t *testing.T) {
	c := NewClient("", "", "", "", nil, nil)
	policy := []byte(`{"data":{"sdpPolicy":{"data":{"clientOption":{"tun0rtt":{"enable":true,"maxIdleConnNum":3,"maxIdleLingerTime":2500}}}}}}`)
	if err := c.parseResource(policy); err != nil {
		t.Fatal(err)
	}
	c.tcpTunnelPool.mu.Lock()
	defer c.tcpTunnelPool.mu.Unlock()
	if !c.tcpTunnelPool.enabled || c.tcpTunnelPool.maxIdle != 3 || c.tcpTunnelPool.idleTTL != 2500*time.Millisecond {
		t.Fatalf("pool config = enabled:%t max:%d ttl:%s", c.tcpTunnelPool.enabled, c.tcpTunnelPool.maxIdle, c.tcpTunnelPool.idleTTL)
	}
}

func TestDisableTCPTunnelPoolOverridesServerPolicy(t *testing.T) {
	c := NewClient("", "", "", "", nil, nil)
	c.SetTCPTunnelPoolDisabled(true)
	policy := []byte(`{"data":{"sdpPolicy":{"data":{"clientOption":{"tun0rtt":{"enable":true,"maxIdleConnNum":3,"maxIdleLingerTime":2500}}}}}}`)
	if err := c.parseResource(policy); err != nil {
		t.Fatal(err)
	}
	c.tcpTunnelPool.mu.Lock()
	defer c.tcpTunnelPool.mu.Unlock()
	if c.tcpTunnelPool.enabled {
		t.Fatal("disabled TCP tunnel pool was enabled by server policy")
	}
}

func TestParseResourcePreservesTCPPrefL3ForDomainAndResolvedIP(t *testing.T) {
	var policy ClientResource
	policy.Data.AppList.Data.AppInfo = append(policy.Data.AppList.Data.AppInfo, struct{ Apps []resourceApp }{
		Apps: []resourceApp{{
			ID: "l3-app", NodeGroupID: "l3-group", AccessModel: "L3VPN", EnableTCPPrefL3: true,
			AddressList: []resourceAddress{{Protocol: "tcp", Port: "443", Host: "internal.example", IP: []string{"10.0.0.42"}}},
		}},
	})
	resource, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	c := &Client{}
	if err := c.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	domainResource, ok := client.MatchDomainResource(c.domainResources["internal.example"], "tcp", 443)
	if !ok || !domainResource.EnableTCPPrefL3 {
		t.Fatalf("domain resource = (%#v, %t), want TCP-prefers-L3", domainResource, ok)
	}
	ipResource, ok := c.resourceIndex.Match(net.ParseIP("10.0.0.42"), "tcp", 443)
	if !ok || !ipResource.EnableTCPPrefL3 || ipResource.AppID != "l3-app" {
		t.Fatalf("resolved IP resource = (%#v, %t), want l3-app TCP-prefers-L3", ipResource, ok)
	}
}

func TestDomainTCPSelectionPrefersTCPTunnelResource(t *testing.T) {
	resources := []client.DomainResource{
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "l3-app", EnableTCPPrefL3: true},
		{PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "tcp-app"},
	}
	resource, ok := client.MatchDomainResourceWhere(resources, "tcp", 443, func(resource client.DomainResource) bool {
		return !resource.EnableTCPPrefL3
	})
	if !ok || resource.AppID != "tcp-app" {
		t.Fatalf("TCP tunnel domain match = (%#v, %t), want tcp-app", resource, ok)
	}
}

func TestParseResourceIgnoresUnsupportedAccessModel(t *testing.T) {
	var policy ClientResource
	policy.Data.AppList.Data.AppInfo = append(policy.Data.AppList.Data.AppInfo, struct{ Apps []resourceApp }{
		Apps: []resourceApp{{
			ID: "web-app", AccessModel: "WEB", AddressList: []resourceAddress{{Protocol: "tcp", Port: "443", Host: "10.0.0.42"}},
		}},
	})
	resource, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	c := &Client{}
	if err := c.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	if _, ok := c.resourceIndex.Match(net.ParseIP("10.0.0.42"), "tcp", 443); ok {
		t.Fatal("unsupported access model unexpectedly became an L3VPN resource")
	}
}
