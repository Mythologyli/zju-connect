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

type Client interface {
	IP() (net.IP, error)
	IPSet() (*netaddr.IPSet, error)
	IPResources() ([]IPResource, error)
	DomainResources() (map[string]DomainResource, error)
	DNSResource() (map[string]net.IP, error)
	DNSServer() (string, error)

	CanUseTCPTunnel() bool
	DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error)
	NewL3Conn() (io.ReadWriteCloser, error)
}
