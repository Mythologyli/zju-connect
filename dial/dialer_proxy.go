package dial

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
	"github.com/things-go/go-socks5/statute"
)

const (
	maxHTTPProxyResponseHeader = 64 << 10
	httpProxyHandshakeTimeout  = 10 * time.Second
)

type bufferedProxyConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedProxyConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (d *Dialer) dialDirectWithoutProxy(ctx context.Context, network, addr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext
	log.Printf("%s -> DIRECT", addr)
	return goDial(ctx, network, addr)
}

// usedAddr maybe ip:port or hostname:port, it doesn't matter
func (d *Dialer) dialDirectWithHTTPProxy(ctx context.Context, usedAddr string) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> PROXY[%s]", usedAddr, d.dialDirectHTTPProxy)
	conn, err := goDial(ctx, "tcp", d.dialDirectHTTPProxy)
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()

	deadline := time.Now().Add(httpProxyHandshakeTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	stopCancel := context.AfterFunc(ctx, func() {
		_ = conn.SetDeadline(time.Now())
	})
	defer stopCancel()

	request := "CONNECT " + usedAddr + " HTTP/1.1\r\nHost: " + usedAddr + "\r\n\r\n"
	if n, err := io.WriteString(conn, request); err != nil {
		return nil, err
	} else if n != len(request) {
		return nil, io.ErrShortWrite
	}

	bufferedConn, err := readHTTPProxyConnectResponse(conn)
	if err != nil {
		return nil, err
	}
	if !stopCancel() {
		return nil, ctx.Err()
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	succeeded = true
	return bufferedConn, nil
}

func readHTTPProxyConnectResponse(conn net.Conn) (net.Conn, error) {
	reader := bufio.NewReader(conn)
	var header bytes.Buffer
	for {
		fragment, err := reader.ReadSlice('\n')
		if header.Len()+len(fragment) > maxHTTPProxyResponseHeader {
			return nil, fmt.Errorf("HTTP proxy response header exceeds %d bytes", maxHTTPProxyResponseHeader)
		}
		_, _ = header.Write(fragment)
		if bytes.HasSuffix(header.Bytes(), []byte("\r\n\r\n")) {
			break
		}
		if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
			return nil, fmt.Errorf("read HTTP proxy response: %w", err)
		}
	}

	request := &http.Request{Method: http.MethodConnect}
	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header.Bytes())), request)
	if err != nil {
		return nil, fmt.Errorf("parse HTTP proxy response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP proxy CONNECT failed: %s", response.Status)
	}

	return &bufferedProxyConn{Conn: conn, reader: reader}, nil
}

func (d *Dialer) dialDirectWithSocksProxy(ctx context.Context, network, usedAddr string, isIP bool) (net.Conn, error) {
	goDialer := &net.Dialer{}
	goDial := goDialer.DialContext

	log.Printf("%s -> PROXY[%s]", usedAddr, d.dialDirectSocksProxy)
	conn, err := goDial(ctx, "tcp", d.dialDirectSocksProxy)
	if err != nil {
		return nil, err
	}
	_, err = conn.Write(statute.NewMethodRequest(statute.VersionSocks5, []byte{statute.MethodNoAuth}).Bytes())
	if err != nil {
		return nil, err
	}
	methodReply, err := statute.ParseMethodReply(conn)
	if err != nil || methodReply.Method != statute.MethodNoAuth || methodReply.Ver != statute.VersionSocks5 {
		return nil, errors.New("SOCKS5 METHOD ERROR")
	}

	parts := strings.Split(usedAddr, ":")
	dstAddr := statute.AddrSpec{}
	if isIP {
		if len(parts) > 2 {
			dstAddr.AddrType = statute.ATYPIPv6
			dstAddr.IP = net.ParseIP(strings.TrimSuffix(usedAddr, ":"+parts[len(parts)-1]))
			if dstAddr.IP == nil {
				return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
			}
			dstAddr.Port, err = strconv.Atoi(parts[len(parts)-1])
			if err != nil {
				return nil, errors.New("Invalid port for socks proxy: " + usedAddr)
			}
		} else if len(parts) == 2 {
			dstAddr.AddrType = statute.ATYPIPv4
			dstAddr.IP = net.ParseIP(parts[0])
			if dstAddr.IP == nil {
				return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
			}
			dstAddr.Port, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("Invalid port for socks proxy: " + usedAddr)
			}
		} else {
			return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
		}
	} else {
		if len(parts) == 2 {
			dstAddr.AddrType = statute.ATYPDomain
			dstAddr.FQDN = parts[0]
			dstAddr.Port, err = strconv.Atoi(parts[1])
			if err != nil {
				return nil, errors.New("Invalid port for socks proxy: " + usedAddr)
			}
		} else {
			return nil, errors.New("Invalid address for socks proxy: " + usedAddr)
		}
	}
	var command byte
	if network == "tcp" {
		command = statute.CommandConnect
	} else {
		// not support yet!
		command = statute.CommandAssociate
	}
	req := statute.Request{
		Version:  statute.VersionSocks5,
		Command:  command,
		Reserved: 0,
		DstAddr:  dstAddr,
	}
	_, err = conn.Write(req.Bytes())
	if err != nil {
		return nil, err
	}
	reply, err := statute.ParseReply(conn)
	if err != nil {
		return nil, err
	}
	if reply.Version != statute.VersionSocks5 || reply.Response != statute.RepSuccess {
		return nil, errors.New("SOCKS5 CONNECT ERROR")
	}
	return conn, nil
}
