package client

import (
	"errors"
	"github.com/beevik/etree"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
	"net"
	"strconv"
	"strings"
)

func (c *EasyConnectClient) parseLineListFromConfig(config string) error {
	log.DebugPrintf("Config: %s", config)

	log.Println("Parsing line list from config...")

	doc := etree.NewDocument()

	err := doc.ReadFromString(config)
	if err != nil {
		return err
	}

	element := doc.SelectElement("Conf").SelectElement("Mline")
	if element == nil {
		return errors.New("no Mline element found")
	}

	if element.SelectAttr("enable") == nil && element.SelectAttr("enable").Value != "1" {
		return errors.New("server disable Mline")
	}

	if element.SelectAttr("list") == nil {
		return errors.New("no list attribute found")
	}

	lineListStr := element.SelectAttr("list").Value
	if lineListStr == "" {
		return errors.New("empty line list")
	}

	lineList := strings.Split(lineListStr, ";")

	for _, line := range lineList {
		if line != "" {
			c.lineList = append(c.lineList, line)
		}
	}

	if len(c.lineList) == 0 {
		return errors.New("empty line list")
	}

	return nil
}

func (c *EasyConnectClient) parseResources(resources string) error {
	log.DebugPrintf("Resources: %s", resources)

	log.Println("Parsing resources...")

	doc := etree.NewDocument()

	err := doc.ReadFromString(resources)
	if err != nil {
		return err
	}

	ipSetBuilder := netaddr.IPSetBuilder{}
	c.ipResources = make([]IPResource, 0)
	c.domainResources = make(map[string]DomainResource)
	c.dnsResource = make(map[string]net.IP)

	element := doc.SelectElement("Resource").SelectElement("Rcs")
	if element == nil {
		return errors.New("no Rcs element found")
	}

	for _, rc := range element.SelectElements("Rc") {
		if rc.SelectAttr("type").Value == "1" || rc.SelectAttr("type").Value == "2" {
			var protocol string
			protoStr := rc.SelectAttr("proto").Value
			if protoStr == "-1" {
				protocol = "all"
			} else if protoStr == "0" {
				protocol = "tcp"
			} else if protoStr == "1" {
				protocol = "udp"
			} else if protoStr == "2" {
				protocol = "icmp"
			} else {
				log.DebugPrintf("Unknown protocol: %s", protoStr)
			}

			hostListStr := rc.SelectAttr("host")
			if hostListStr == nil {
				continue
			}
			hostList := strings.Split(hostListStr.Value, ";")

			portRangeListStr := rc.SelectAttr("port")
			if portRangeListStr == nil {
				continue
			}
			portRangeList := strings.Split(portRangeListStr.Value, ";")

			if len(hostList) != len(portRangeList) {
				log.DebugPrintln("Host and port list length mismatch, skip")
				continue
			}

			for i, host := range hostList {
				portRangeStr := portRangeList[i]
				portRange := strings.Split(portRangeStr, "~")
				if len(portRange) != 2 {
					log.DebugPrintf("Invalid port range: %s", portRangeStr)
					continue
				}
				portMin, err := strconv.Atoi(portRange[0])
				if err != nil {
					log.DebugPrintf("Invalid port range: %s", portRangeStr)
					continue
				}
				portMax, err := strconv.Atoi(portRange[1])
				if err != nil {
					log.DebugPrintf("Invalid port range: %s", portRangeStr)
					continue
				}

				isDomain := false
				var ipMin net.IP
				var ipMax net.IP
				var hostPort string
				if strings.Contains(host, "~") {
					ipList := strings.Split(host, "~")
					if len(ipList) != 2 {
						log.DebugPrintf("Invalid IP range: %s", host)
						continue
					}
					ipMin = net.ParseIP(ipList[0])
					if ipMin == nil {
						log.DebugPrintf("Invalid IP range: %s", host)
						continue
					}
					ipMax = net.ParseIP(ipList[1])

					if ipMax == nil {
						log.DebugPrintf("Invalid IP range: %s", host)
						continue
					}

					ipSetBuilder.AddRange(netaddr.IPRangeFrom(netaddr.MustParseIP(ipList[0]), netaddr.MustParseIP(ipList[1])))
					log.DebugPrintf("Add IP range: %s ~ %s, Port range: %d ~ %d, [%s]", ipList[0], ipList[1], portMin, portMax, protocol)
				} else {
					if strings.Contains(host, "//") {
						host = strings.Split(host, "//")[1]
					}
					host = strings.Split(host, "/")[0]
					if strings.Contains(host, ":") {
						host, hostPort, err = net.SplitHostPort(host)
					}
					ipMin = net.ParseIP(host)
					if ipMin == nil {
						isDomain = true

						if !c.useDomainResource {
							continue
						}

						log.DebugPrintf("Add domain: %s, Port range: %d ~ %d, [%s]", host, portMin, portMax, protocol)
					} else {
						ipMax = ipMin
						if hostPortInt, err := strconv.Atoi(hostPort); hostPort != "" && err == nil {
							portMin = hostPortInt
							portMax = hostPortInt
						}

						ipSetBuilder.Add(netaddr.MustParseIP(host))
						log.DebugPrintf("Add IP: %s, Port range: %d ~ %d, [%s]", host, portMin, portMax, protocol)
					}
				}

				if isDomain {
					c.domainResources[host] = DomainResource{
						PortMin:  portMin,
						PortMax:  portMax,
						Protocol: protocol,
					}
				} else {
					c.ipResources = append(c.ipResources, IPResource{
						IPMin:    ipMin,
						IPMax:    ipMax,
						PortMin:  portMin,
						PortMax:  portMax,
						Protocol: protocol,
					})
				}
			}
		}
	}

	element = doc.SelectElement("Resource").SelectElement("Dns")
	if element == nil {
		return errors.New("no Rcs element found")
	}

	dnsListStr := element.SelectAttr("data")
	if dnsListStr == nil {
		return errors.New("no Dns data attribute found")
	}

	for _, dnsStr := range strings.Split(dnsListStr.Value, ";") {
		if dnsStr == "" {
			continue
		}

		dnsParts := strings.Split(dnsStr, ":")
		if len(dnsParts) != 3 {
			continue
		}

		ip, err := netaddr.ParseIP(dnsParts[2])
		if err != nil {
			continue
		}

		c.dnsResource[dnsParts[1]] = ip.IPAddr().IP
		log.DebugPrintf("Add DNS rule: %s -> %s", dnsParts[1], dnsParts[2])
	}

	c.ipSet, err = ipSetBuilder.IPSet()
	if err != nil {
		return err
	}

	dnsServerStr := element.SelectAttr("dnsserver")
	if dnsServerStr == nil {
		return errors.New("no Dns dnsserver attribute found")
	}

	c.dnsServer = strings.Split(dnsServerStr.Value, ";")[0]

	if c.dnsServer == "0.0.0.0" {
		c.dnsServer = ""
		return errors.New("DNS server invalid")
	}

	return nil
}
