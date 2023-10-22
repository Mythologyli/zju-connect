package core

import (
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
)

func ServeTcpForwarding(bindAddress string, remoteAddress string, client *EasyConnectClient) {

	ln, err := net.Listen("tcp", bindAddress)
	if err != nil {
		panic(err)
	}

	if TunMode {
		for {
			conn, err := ln.Accept()
			if err != nil {
				panic(err)
			}

			go handleRequestWithTun(conn, remoteAddress, client.clientIp)
		}
	} else {
		for {
			conn, err := ln.Accept()
			if err != nil {
				panic(err)
			}

			go handleRequestWithGvisor(conn, remoteAddress, client.gvisorStack, client.clientIp)
		}
	}
}

func handleRequestWithGvisor(conn net.Conn, remoteAddress string, ipStack *stack.Stack, selfIp []byte) {
	log.Printf("Port forwarding (tcp): %s -> %s -> %s", conn.RemoteAddr(), conn.LocalAddr(), remoteAddress)

	parts := strings.Split(remoteAddress, ":")
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}

	addrTarget := tcpip.FullAddress{
		NIC:  defaultNIC,
		Port: uint16(port),
		Addr: tcpip.AddrFromSlice(net.ParseIP(host).To4()),
	}

	bind := tcpip.FullAddress{
		NIC:  defaultNIC,
		Addr: tcpip.AddrFromSlice(selfIp),
	}

	proxy, err := gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
	if err != nil {
		panic(err)
	}

	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}

func handleRequestWithTun(conn net.Conn, remoteAddress string, selfIp []byte) {
	log.Printf("Port forwarding (tcp): %s -> %s -> %s", conn.RemoteAddr(), conn.LocalAddr(), remoteAddress)

	parts := strings.Split(remoteAddress, ":")
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}

	addrTarget := net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	}

	bind := net.TCPAddr{
		IP:   net.IP(selfIp),
		Port: 0,
	}

	proxy, err := net.DialTCP("tcp", &bind, &addrTarget)
	if err != nil {
		panic(err)
	}

	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}

func copyIO(src, dest net.Conn) {
	defer src.Close()
	defer dest.Close()
	io.Copy(src, dest)
}
