package atrust

import (
	"github.com/mythologyli/zju-connect/client"
	"inet.af/netaddr"
	"net"
)

type Client struct {
	Username string
	SID      string
	DeviceID string
	SignKey  string

	resources []byte

	ipResources     []client.IPResource
	domainResources map[string]client.DomainResource
	ipSet           *netaddr.IPSet
	dnsResource     map[string]net.IP
	dnsServer       string

	NodeGroups map[string][]string
}

func NewClient(username, sid, deviceID, signKey string, resources []byte) *Client {
	return &Client{
		Username:  username,
		SID:       sid,
		DeviceID:  deviceID,
		SignKey:   signKey,
		resources: resources,
	}
}

func (c *Client) IPSet() (*netaddr.IPSet, error) {
	if c.ipSet == nil {
		return nil, nil
	}
	return c.ipSet, nil
}

func (c *Client) IPResources() ([]client.IPResource, error) {
	if c.ipResources == nil {
		return nil, nil
	}
	return c.ipResources, nil
}

func (c *Client) DomainResources() (map[string]client.DomainResource, error) {
	if c.domainResources == nil {
		return nil, nil
	}
	return c.domainResources, nil
}

func (c *Client) DNSResource() (map[string]net.IP, error) {
	if c.dnsResource == nil {
		return nil, nil
	}
	return c.dnsResource, nil
}

func (c *Client) DNSServer() (string, error) {
	if c.dnsServer == "" {
		return "", nil
	}
	return c.dnsServer, nil
}

func (c *Client) Setup() error {
	if c.resources != nil {
		err := c.parseResource(c.resources)
		if err != nil {
			return err
		}
	}

	return nil
}
