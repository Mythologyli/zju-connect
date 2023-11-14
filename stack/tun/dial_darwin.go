package tun

import (
	"net"
	"net/netip"
)

var zjuRouterPrefix = netip.MustParsePrefix("10.0.0.0/8")

func (s *Stack) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	if zjuRouterPrefix.Contains(addr.AddrPort().Addr()) {
		return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
	}
	return net.DialTCP("tcp4", nil, addr)
}

func (s *Stack) DialUDP(addr *net.UDPAddr) (net.Conn, error) {
	if zjuRouterPrefix.Contains(addr.AddrPort().Addr()) {
		return s.endpoint.udpDialer.Dial("udp4", addr.String())
	}
	return net.DialUDP("udp4", nil, addr)
}
