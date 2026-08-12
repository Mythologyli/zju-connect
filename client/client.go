package client

import (
	"context"
	"errors"
	"io"
	"net"

	"inet.af/netaddr"
)

var ErrResourceNotFound = errors.New("resource not found")

type IPResource struct {
	IPMin       net.IP
	IPMax       net.IP
	PortMin     int
	PortMax     int
	Protocol    string
	AppID       string
	NodeGroupID string
}

type DomainResource struct {
	PortMin     int
	PortMax     int
	Protocol    string
	AppID       string
	NodeGroupID string
}

type DomainResources map[string][]DomainResource

func MatchDomainResource(resources []DomainResource, network string, port int) (DomainResource, bool) {
	for _, resource := range resources {
		protocolMatches := resource.Protocol == network || resource.Protocol == "all"
		portMatches := network == "icmp" || resource.PortMin <= port && port <= resource.PortMax
		if protocolMatches && portMatches {
			return resource, true
		}
	}
	return DomainResource{}, false
}

type Client interface {
	IP() (net.IP, error)
	IPSet() (*netaddr.IPSet, error)
	IPResources() ([]IPResource, error)
	DomainResources() (DomainResources, error)
	DNSResource() (map[string][]net.IP, error)
	DNSServer() (string, error)
	DNSServers() ([]string, error)

	CanUseTCPTunnel() bool
	DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error)
	NewL3Conn() (io.ReadWriteCloser, error)
}

type IPUpdateHandlerSetter interface {
	SetIPUpdateHandler(func(net.IP) error)
}

func RegisterIPUpdateHandler(c Client, handler func(net.IP) error) bool {
	setter, ok := c.(IPUpdateHandlerSetter)
	if ok {
		setter.SetIPUpdateHandler(handler)
	}
	return ok
}
