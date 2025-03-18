package tun

import (
	"inet.af/netaddr"
	"net"
)

func (s *Stack) DialTCP(addr *net.TCPAddr) (net.Conn, error) {
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.tcpDialer.Dial("tcp4", addr.String())
	}
	return net.DialTCP("tcp4", nil, addr)
}

func (s *Stack) DialUDP(addr *net.UDPAddr) (net.Conn, error) {
	prefix, ok := netaddr.FromStdIP(addr.IP)
	if ok && s.endpoint.ipSet.Contains(prefix) {
		return s.endpoint.udpDialer.Dial("udp4", addr.String())
	}
	return net.DialUDP("udp4", nil, addr)
}
