package stack

import "net"

type Stack interface {
	Run()
	DialTCP(addr *net.TCPAddr) (net.Conn, error)
	DialUDP(addr *net.UDPAddr) (net.Conn, error)
}
