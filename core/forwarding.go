package core

import (
	"context"
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

func ServeForwarding(networkType string, bindAddress string, remoteAddress string, ipStack *stack.Stack, selfIp []byte) {
	if networkType != "tcp" {
		log.Println("Only TCP forwarding is supported yet. Aborting.")
		return
	}

	ln, err := net.Listen(networkType, bindAddress)
	if err != nil {
		panic(err)
	}

	log.Printf("Port forwarding (%s): %s <- %s", networkType, bindAddress, remoteAddress)

	for {
		conn, err := ln.Accept()
		if err != nil {
			panic(err)
		}

		go handleRequest(conn, remoteAddress, ipStack, selfIp)
	}
}

func handleRequest(conn net.Conn, remoteAddress string, ipStack *stack.Stack, selfIp []byte) {
	log.Printf("Port forwarding (%s): %s -> %s -> %s", conn.LocalAddr().Network(), conn.RemoteAddr(), conn.LocalAddr(), remoteAddress)

	parts := strings.Split(remoteAddress, ":")
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}

	addrTarget := tcpip.FullAddress{
		NIC:  defaultNIC,
		Port: uint16(port),
		Addr: tcpip.Address(net.ParseIP(host).To4()),
	}

	bind := tcpip.FullAddress{
		NIC:  defaultNIC,
		Addr: tcpip.Address(selfIp),
	}

	proxy, err := gonet.DialTCPWithBind(context.Background(), ipStack, bind, addrTarget, header.IPv4ProtocolNumber)
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
