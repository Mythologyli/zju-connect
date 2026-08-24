package atrust

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func parseIPAuthResponse(data []byte) error {
	var response authResponseSID
	if err := json.Unmarshal(data, &response); err != nil {
		return fmt.Errorf("failed to parse IP tunnel auth response: %w", err)
	}
	if response.Code != 0 {
		return fmt.Errorf("IP tunnel authentication failed (code %d): %s", response.Code, response.Message)
	}
	return nil
}

func parseIPv4VIPResponse(data []byte) (net.IP, error) {
	if len(data) != 6 {
		return nil, fmt.Errorf("unexpected IPv4 VIP response length: %d", len(data))
	}
	if data[1] != 0x01 {
		return nil, fmt.Errorf("unexpected IPv4 VIP response: %x", data)
	}
	return net.IPv4(data[2], data[3], data[4], data[5]), nil
}

func readIPTunnelResponses(reader io.Reader) (net.IP, error) {
	method := make([]byte, 2)
	if _, err := io.ReadFull(reader, method); err != nil {
		return nil, err
	}
	if method[0] != 0x05 || method[1] != 0xD0 {
		return nil, fmt.Errorf("unexpected IP tunnel auth method response: %x", method)
	}

	authHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, authHeader); err != nil {
		return nil, err
	}
	if authHeader[0] != 0x53 {
		return nil, fmt.Errorf("unexpected IP tunnel auth response version: 0x%02x", authHeader[0])
	}
	authLength := int(binary.BigEndian.Uint16(authHeader[2:4]))
	authPayload := make([]byte, authLength)
	if _, err := io.ReadFull(reader, authPayload); err != nil {
		return nil, err
	}
	if authHeader[1] != 0 {
		return nil, fmt.Errorf("IP tunnel authentication status %d", authHeader[1])
	}
	if err := parseIPAuthResponse(authPayload); err != nil {
		return nil, err
	}

	vipHeader := make([]byte, 4)
	if _, err := io.ReadFull(reader, vipHeader); err != nil {
		return nil, err
	}
	vipLength, err := parseInitialVIPHeader(vipHeader)
	if err != nil {
		return nil, err
	}
	if vipLength != 6 {
		return nil, fmt.Errorf("unexpected non-IPv4 VIP response")
	}
	vipData := make([]byte, vipLength)
	if _, err := io.ReadFull(reader, vipData); err != nil {
		return nil, err
	}
	return net.IPv4(vipData[0], vipData[1], vipData[2], vipData[3]), nil
}

func (c *Client) getIP() error {
	addr := c.BestNodes[c.MajorNodeGroup]
	if addr == "" {
		for _, node := range c.BestNodes {
			addr = node
			break
		}
	}
	if addr == "" {
		return fmt.Errorf("no reachable node for ip request")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialTLSContext(ctx, c.underlayDialer, "tcp", addr, tunnelTLSConfig(c.tlsKeyLogWriter))
	if err != nil {
		return err
	}
	defer func(conn *tls.Conn) {
		_ = conn.Close()
	}(conn)

	authPayload, err := json.Marshal(authRequestSID{Sid: c.SID})
	if err != nil {
		return fmt.Errorf("failed to marshal IP tunnel auth request: %w", err)
	}
	msg := wrapAuthReqData(authPayload, 1)
	if _, err := conn.Write(msg); err != nil {
		return err
	}

	if err := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return err
	}
	ip, err := readIPTunnelResponses(conn)
	if err != nil {
		return err
	}
	c.setIP(ip)
	log.Printf("Received IP: %s", ip.String())
	return nil
}
