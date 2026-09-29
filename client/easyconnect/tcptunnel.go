package easyconnect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

func (c *Client) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil || addr.IP.To4() == nil || addr.Port < 1 || addr.Port > 65535 {
		return nil, errors.New("TCP tunnel requires a valid IPv4 destination")
	}
	if c.twfID == "" {
		return nil, errors.New("TCP tunnel requires an authenticated session")
	}

	timeout := c.rawRequestTimeout
	if timeout <= 0 {
		timeout = easyConnectRawRequestTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := c.tlsConn(ctx, "TCPP")
	if err != nil {
		return nil, err
	}
	succeeded := false
	defer func() {
		if !succeeded {
			_ = conn.Close()
		}
	}()
	clearDeadline, err := armConnectionContext(ctx, conn)
	if err != nil {
		return nil, err
	}
	defer clearDeadline()

	commands := []struct {
		code    string
		message string
	}{
		{"C01", "C01 HELLO\r\nCLIENT: WINDOWS/10.0\r\n\r\n"},
		{"C02", "C02 AUTH SESSION\r\nID: " + c.twfID + "\r\n\r\n"},
		{"C03", fmt.Sprintf("C03 CONNECT RESOURCE\r\nVER: 4\r\nDST: %s %d\r\nTYPE: GENERAL\r\n\r\n", addr.IP.String(), addr.Port)},
	}
	for _, command := range commands {
		if _, err := io.WriteString(conn, command.message); err != nil {
			return nil, fmt.Errorf("TCP tunnel %s: %w", command.code, err)
		}

		// Stop at the header boundary so application data stays in conn.
		reply := make([]byte, 0, 128)
		var b [1]byte
		for !bytes.HasSuffix(reply, []byte("\r\n\r\n")) {
			if len(reply) >= 4096 {
				return nil, fmt.Errorf("TCP tunnel %s: response header too large", command.code)
			}
			if _, err := io.ReadFull(conn, b[:]); err != nil {
				return nil, fmt.Errorf("TCP tunnel %s: read response: %w", command.code, err)
			}
			reply = append(reply, b[0])
		}
		if !strings.HasPrefix(string(reply), command.code+" OK\r\n") {
			return nil, fmt.Errorf("TCP tunnel %s: unexpected response %q", command.code, reply)
		}
	}

	succeeded = true
	return conn, nil
}
