package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/stack"
)

func handleRequest(stack stack.Stack, conn net.Conn, remoteAddress string) {
	log.Printf("Port forwarding (TCP): %s -> %s -> %s", conn.RemoteAddr(), conn.LocalAddr(), remoteAddress)

	parts := strings.Split(remoteAddress, ":")
	host := parts[0]
	port, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(err)
	}

	proxy, err := stack.DialTCP(context.Background(), &net.TCPAddr{
		IP:   net.ParseIP(host),
		Port: port,
	})
	if err != nil {
		panic(err)
	}

	go copyIO(conn, proxy)
	go copyIO(proxy, conn)
}

func copyIO(src, dest net.Conn) {
	defer func(src net.Conn) {
		_ = src.Close()
	}(src)
	defer func(dest net.Conn) {
		_ = dest.Close()
	}(dest)
	_, _ = io.Copy(src, dest)
}

func ServeTCPForwarding(stack stack.Stack, bindAddress string, remoteAddress string) {
	ln, err := net.Listen("tcp", bindAddress)
	if err != nil {
		panic(err)
	}

	log.Printf("TCP port forwarding: %s -> %s", bindAddress, remoteAddress)

	hook_func.RegisterTerminalFunc("CloseTCPForwardingPort", func(ctx context.Context) error {
		log.Println("Closing TCP forwarding port...")
		if err := ln.Close(); err != nil {
			return fmt.Errorf("close TCP forwarding listener failed: %w", err)
		}
		return nil
	})

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				log.Println("TCP forwarding port closed")
				return
			}
			panic(err)
		}

		go handleRequest(stack, conn, remoteAddress)
	}
}
