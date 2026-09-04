package service

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/hook_func"
	"github.com/mythologyli/zju-connect/log"
)

func handleTCPForwardingRequest(dialContext client.DialContextFunc, conn net.Conn, remoteAddress string) {
	log.Printf("Port forwarding (TCP): %s -> %s -> %s", conn.RemoteAddr(), conn.LocalAddr(), remoteAddress)

	proxy, err := dialContext(context.Background(), "tcp", remoteAddress)
	if err != nil {
		log.Printf("Port forwarding (TCP) dial %s failed: %v", remoteAddress, err)
		_ = conn.Close()
		return
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

func ServeTCPForwarding(dialContext client.DialContextFunc, bindAddress string, remoteAddress string) {
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

		go handleTCPForwardingRequest(dialContext, conn, remoteAddress)
	}
}
