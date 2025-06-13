package client

import (
	"inet.af/netaddr"
	"net"
)

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

type Client interface {
	Setup() error
	IPSet() (*netaddr.IPSet, error)
	IPResources() ([]IPResource, error)
	DomainResources() (map[string]DomainResource, error)
	DNSResource() (map[string]net.IP, error)
	DNSServer() (string, error)
}
