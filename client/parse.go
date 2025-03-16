package client

import (
	"errors"
	"github.com/beevik/etree"
	"github.com/mythologyli/zju-connect/log"
	"inet.af/netaddr"
	"net"
	"strings"
)

func (c *EasyConnectClient) parseLineListFromConfig(config string) error {
	log.Println("Parsing line list from config")

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
	log.Println("Parsing resources...")

	doc := etree.NewDocument()

	err := doc.ReadFromString(resources)
	if err != nil {
		return err
	}

	ipSetBuilder := netaddr.IPSetBuilder{}
	c.domainResource = make(map[string]bool)
	c.dnsResource = make(map[string]net.IP)

	element := doc.SelectElement("Resource").SelectElement("Rcs")
	if element == nil {
		return errors.New("no Rcs element found")
	}

	for _, rc := range element.SelectElements("Rc") {
		hostListStr := rc.SelectAttr("host")
		if hostListStr == nil {
			continue
		}

		for _, hostStr := range strings.Split(hostListStr.Value, ";") {
			if strings.Contains(hostStr, "*") {
				hostStr = strings.ReplaceAll(hostStr, "*", "")
			}

			if hostStr == "" {
				continue
			}

			// IP range
			if strings.Contains(hostStr, "~") {
				startIPStr := strings.Split(hostStr, "~")[0]
				endIPStr := strings.Split(hostStr, "~")[1]

				startIP, err := netaddr.ParseIP(startIPStr)
				if err != nil {
					continue
				}

				endIP, err := netaddr.ParseIP(endIPStr)
				if err != nil {
					continue
				}

				ipSetBuilder.AddRange(netaddr.IPRangeFrom(startIP, endIP))

				log.DebugPrintf("Add IP range: %s ~ %s", startIPStr, endIPStr)

				continue
			}

			// Domain
			if strings.Contains(hostStr, "//") {
				hostStr = strings.Split(hostStr, "//")[1]
			}

			hostStr := strings.Split(hostStr, "/")[0]
			ip, err := netaddr.ParseIP(hostStr)
			if err != nil {
				if c.useDomainResource {
					if hostStr == "" {
						continue
					}

					c.domainResource[hostStr] = true

					log.DebugPrintf("Add domain: %s", hostStr)
				}
			} else {
				ipSetBuilder.Add(ip)

				log.DebugPrintf("Add IP: %s", hostStr)
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

		ipSetBuilder.Add(ip)

		c.dnsResource[dnsParts[1]] = ip.IPAddr().IP
		log.DebugPrintf("Add DNS rule: %s -> %s", dnsParts[1], dnsParts[2])
	}

	c.ipResource, err = ipSetBuilder.IPSet()
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
