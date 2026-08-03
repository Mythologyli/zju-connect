package atrust

import (
	"reflect"
	"testing"
)

func TestParseResourceSeparatesWANAndLANNodes(t *testing.T) {
	client := NewClient("", "", "", "")
	client.serverAddress = "vpn.example.com"
	resource := []byte(`{
		"data": {
			"appList": {
				"data": {
					"config": {
						"nodeGroupConf": {
							"majorNodeGroup": {"id": "group"},
							"nodeGroupList": [{
								"id": "group",
								"addressInfo": [
									{"address": "wan.example.com:441", "type": "wan"},
									{"address": "lan.example.com:441", "type": "lan"}
								]
							}]
						}
					}
				}
			}
		}
	}`)

	if err := client.parseResource(resource); err != nil {
		t.Fatalf("parseResource() error = %v", err)
	}
	if got, want := client.NodeGroups["group"].WAN, []string{"wan.example.com:441"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("WAN nodes = %v, want %v", got, want)
	}
	if got, want := client.NodeGroups["group"].LAN, []string{"lan.example.com:441"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("LAN nodes = %v, want %v", got, want)
	}
}

func TestSelectBestNodesPrefersReachableWAN(t *testing.T) {
	nodeGroups := map[string]NodeGroup{
		"group": {
			WAN: []string{"wan-a:441", "wan-b:441"},
			LAN: []string{"lan-a:441"},
		},
	}
	wanNodeGroups := map[string][]string{"group": {"wan-a:441", "wan-b:441"}}
	var probed []map[string][]string

	got := selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		probed = append(probed, nodeGroups)
		return map[string]string{"group": "wan-b:441"}
	})

	if got["group"] != "wan-b:441" {
		t.Fatalf("selected node = %q, want reachable WAN node", got["group"])
	}
	if len(probed) != 1 || !reflect.DeepEqual(probed[0], wanNodeGroups) {
		t.Fatalf("probed node groups = %v, want only WAN nodes", probed)
	}
}

func TestSelectBestNodesFallsBackToLANWhenWANUnreachable(t *testing.T) {
	nodeGroups := map[string]NodeGroup{
		"group": {
			WAN: []string{"wan-a:441"},
			LAN: []string{"lan-a:441", "lan-b:441"},
		},
	}
	wanNodeGroups := map[string][]string{"group": {"wan-a:441"}}
	lanNodeGroups := map[string][]string{"group": {"lan-a:441", "lan-b:441"}}
	var probed []map[string][]string

	got := selectBestNodes(nodeGroups, func(nodeGroups map[string][]string) map[string]string {
		probed = append(probed, nodeGroups)
		if reflect.DeepEqual(nodeGroups, lanNodeGroups) {
			return map[string]string{"group": "lan-b:441"}
		}
		return map[string]string{}
	})

	if got["group"] != "lan-b:441" {
		t.Fatalf("selected node = %q, want reachable LAN node", got["group"])
	}
	wantProbed := []map[string][]string{wanNodeGroups, lanNodeGroups}
	if !reflect.DeepEqual(probed, wantProbed) {
		t.Fatalf("probed node groups = %v, want %v", probed, wantProbed)
	}
}

func TestSelectBestNodesOmitsGroupWhenNoNodeReachable(t *testing.T) {
	got := selectBestNodes(
		map[string]NodeGroup{
			"group": {
				WAN: []string{"wan-a:441"},
				LAN: []string{"lan-a:441"},
			},
		},
		func(map[string][]string) map[string]string {
			return map[string]string{}
		},
	)

	if _, ok := got["group"]; ok {
		t.Fatalf("selected unreachable node %q", got["group"])
	}
}
