package atrust

import (
	"encoding/json"
	"testing"

	"github.com/mythologyli/zju-connect/client"
)

func TestParseResourcePreservesMultipleRulesForDomain(t *testing.T) {
	var policy ClientResource
	appInfo := struct {
		Apps []struct {
			ID          string
			NodeGroupID string
			AddressList []struct {
				Protocol string
				Port     string
				Host     string
				IP       []string
			}
		}
	}{}
	for _, rule := range []struct{ id, group, port string }{
		{id: "https-app", group: "https-group", port: "443"},
		{id: "http-app", group: "http-group", port: "80"},
	} {
		var app struct {
			ID          string
			NodeGroupID string
			AddressList []struct {
				Protocol string
				Port     string
				Host     string
				IP       []string
			}
		}
		app.ID, app.NodeGroupID = rule.id, rule.group
		app.AddressList = append(app.AddressList, struct {
			Protocol string
			Port     string
			Host     string
			IP       []string
		}{Protocol: "tcp", Port: rule.port, Host: "www.cnki.net"})
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
