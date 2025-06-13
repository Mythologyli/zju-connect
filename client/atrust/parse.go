package atrust

import (
	"encoding/json"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
	"net"
	"strconv"
	"strings"
)

type ClientResource struct {
	Data struct {
		AppList struct {
			Data struct {
				AppInfo []struct {
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
				}

				Config struct {
					NodeGroupConf struct {
						NodeGroupList []struct {
							AddressInfo []struct {
								Address string
								Type    string
							}
							ID string
						}
					}
				}
			}
		}

		SDPPolicy struct {
			Data struct {
				ClientOption struct {
					DNSOption struct {
						FirstDNS  string
						SecondDNS string
					}

					DNSOptionV2 struct {
						FirstDNS  string
						SecondDNS string
					}
				}
			}
		}
	}
}

func (c *Client) parseResource(resource []byte) error {
	log.Println("Parsing resource...")

	var clientResource ClientResource
	err := json.Unmarshal(resource, &clientResource)
	if err != nil {
		return err
	}

	ipSetBuilder := netaddr.IPSetBuilder{}
	c.ipResources = make([]client.IPResource, 0)
	c.domainResources = make(map[string]client.DomainResource)
	c.dnsResource = make(map[string]net.IP)

	for _, app := range clientResource.Data.AppList.Data.AppInfo {
		for _, appItem := range app.Apps {
			for _, address := range appItem.AddressList {
				if address.Protocol == "tcp" || address.Protocol == "udp" || address.Protocol == "all" {
					// Handle port
					portStr := address.Port
					var portMin, portMax int
					if strings.Contains(portStr, "-") {
						// Handle port range
						ports := strings.Split(portStr, "-")
						if len(ports) != 2 {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
						portMin, err = strconv.Atoi(ports[0])
						if err != nil {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
						portMax, err = strconv.Atoi(ports[1])
						if err != nil {
							log.DebugPrintf("invalid port range: %s", portStr)
							continue
						}
					} else {
						// Handle single port
						portMin, err = strconv.Atoi(portStr)
						if err != nil {
							log.DebugPrintf("invalid port: %s", portStr)
							continue
						}
						portMax = portMin // Single port means min and max are the same
					}

					// Handle host
					hostStr := address.Host
					isDomain := false
					// First, try to parse the host as an IP address
					ip := net.ParseIP(hostStr)
					if ip == nil {
						ipParts := strings.Split(hostStr, "-")
						if len(ipParts) == 2 {
							ipMin := net.ParseIP(ipParts[0])
							ipMax := net.ParseIP(ipParts[1])
							if ipMin != nil && ipMax != nil {
								// It's a range of IP addresses
								if ipMin.To4() != nil {
									ipSetBuilder.AddRange(netaddr.IPRangeFrom(netaddr.MustParseIP(ipMin.String()), netaddr.MustParseIP(ipMax.String())))

									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin:       ipMin,
										IPMax:       ipMax,
										PortMin:     portMin,
										PortMax:     portMax,
										Protocol:    address.Protocol,
										AppID:       appItem.ID,
										NodeGroupID: appItem.NodeGroupID,
									})

									log.DebugPrintf("Add IP range: %s ~ %s, Port range: %d ~ %d, [%s]", ipMin, ipMax, portMin, portMax, address.Protocol)
								} else {
									log.DebugPrintf("IPv6 address range found: %s ~ %s, skipping", ipMin, ipMax)
								}
							} else {
								isDomain = true
							}
						} else {
							isDomain = true
						}
					} else {
						// It's an IP address
						if ip.To4() != nil {
							ipSetBuilder.Add(netaddr.MustParseIP(ip.String()))

							c.ipResources = append(c.ipResources, client.IPResource{
								IPMin:       ip,
								IPMax:       ip,
								PortMin:     portMin,
								PortMax:     portMax,
								Protocol:    address.Protocol,
								AppID:       appItem.ID,
								NodeGroupID: appItem.NodeGroupID,
							})

							log.DebugPrintf("Add IP: %s, Port range: %d ~ %d, [%s]", ip, portMin, portMax, address.Protocol)
						} else {
							log.DebugPrintf("IPv6 address found: %s, skipping", ip)
						}
					}

					if isDomain {
						hostStr = strings.ReplaceAll(hostStr, "*", "")

						c.domainResources[hostStr] = client.DomainResource{
							PortMin:     portMin,
							PortMax:     portMax,
							Protocol:    address.Protocol,
							AppID:       appItem.ID,
							NodeGroupID: appItem.NodeGroupID,
						}

						log.DebugPrintf("Add domain: %s, Port range: %d ~ %d, [%s]", hostStr, portMin, portMax, address.Protocol)
					}

					// Handle IP addresses
					if address.IP != nil {
						for _, ipStr := range address.IP {
							ip := net.ParseIP(ipStr)
							if ip != nil {
								if ip.To4() != nil {
									c.ipResources = append(c.ipResources, client.IPResource{
										IPMin:       ip,
										IPMax:       ip,
										PortMin:     portMin,
										PortMax:     portMax,
										Protocol:    address.Protocol,
										AppID:       appItem.ID,
										NodeGroupID: appItem.NodeGroupID,
									})

									ipSetBuilder.Add(netaddr.MustParseIP(ip.String()))
									log.DebugPrintf("Add IP: %s, Port range: %d ~ %d, [%s]", ip, portMin, portMax, address.Protocol)
								} else {
									log.DebugPrintf("IPv6 address found: %s, skipping", ip)
								}
							} else {
								log.DebugPrintf("Invalid IP: %s", ipStr)
							}
						}
					}
				}
			}
		}
	}

	c.ipSet, _ = ipSetBuilder.IPSet()
	if clientResource.Data.SDPPolicy.Data.ClientOption.DNSOption.FirstDNS != "" {
		c.dnsServer = clientResource.Data.SDPPolicy.Data.ClientOption.DNSOption.FirstDNS
		log.DebugPrintf("Set DNS server: %s", c.dnsServer)
	} else if clientResource.Data.SDPPolicy.Data.ClientOption.DNSOptionV2.FirstDNS != "" {
		c.dnsServer = clientResource.Data.SDPPolicy.Data.ClientOption.DNSOptionV2.FirstDNS
		log.DebugPrintf("Set DNS server: %s", c.dnsServer)
	} else {
		log.DebugPrintf("No DNS server found")
	}

	c.NodeGroups = make(map[string][]string)
	for _, nodeGroup := range clientResource.Data.AppList.Data.Config.NodeGroupConf.NodeGroupList {
		addressList := make([]string, 0)
		for _, addressInfo := range nodeGroup.AddressInfo {
			if addressInfo.Type == "wan" {
				addressList = append(addressList, addressInfo.Address)
			}
		}
		c.NodeGroups[nodeGroup.ID] = addressList
		log.DebugPrintf("Node Group ID: %s, Addresses: %v", nodeGroup.ID, addressList)
	}

	return nil
}
