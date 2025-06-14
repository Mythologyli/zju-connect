package atrust

import (
	"bufio"
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
	"io"
	"net"
	"strings"
	"time"
)

type atrustConn struct {
	tlsConn *tls.Conn
	reader  *bufio.Reader
	readBuf []byte
}

func (c *atrustConn) Read(b []byte) (int, error) {
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		header := make([]byte, 2)
		_, err := io.ReadFull(c.reader, header)
		if err != nil {
			return 0, err
		}
		log.DebugPrint("Received header: ", fmt.Sprintf("%02X %02X", header[0], header[1]))
		if header[0] == 0x01 && header[1] == 0x00 {
			lengthBytes := make([]byte, 2)
			_, err = io.ReadFull(c.reader, lengthBytes)
			if err != nil {
				return 0, err
			}
			length := binary.BigEndian.Uint16(lengthBytes)
			data := make([]byte, length)
			_, err = io.ReadFull(c.reader, data)
			if err != nil {
				return 0, err
			}
			log.DebugPrint("Received application data, length:", length)
			log.DebugDumpHex(data)

			n := copy(b, data)
			if n < len(data) {
				c.readBuf = data[n:]
			}

			return n, nil
		} else if header[0] == 0x01 && header[1] == 0x01 {
			header = make([]byte, 2)
			_, err = io.ReadFull(c.reader, header)
			if err != nil {
				return 0, err
			}

			if header[0] == 0x30 && header[1] == 0x30 {
				log.DebugPrint("Received close message")
				_ = c.tlsConn.Close()
				return 0, fmt.Errorf("connection closed by server")
			}
		} else if header[0] == 0x53 && header[1] == 0x00 {
			lengthBytes := make([]byte, 2)
			_, err = io.ReadFull(c.reader, lengthBytes)
			if err != nil {
				return 0, err
			}
			length := binary.BigEndian.Uint16(lengthBytes)

			data := make([]byte, length)
			_, err = io.ReadFull(c.reader, data)
			if err != nil {
				return 0, err
			}

			log.DebugPrint("Received protocol response:")
			log.DebugDumpHex(data)

			if !strings.Contains(string(data), "OK") {
				log.Printf("Failed to connect to the server: %s", string(data))
				_ = c.tlsConn.Close()
				return 0, fmt.Errorf("failed to connect to the server")
			}
		}
	}
}

func (c *atrustConn) Write(b []byte) (int, error) {
	header := []byte{0x01, 0x00}
	length := len(b)
	if length > 0xFFFF {
		return 0, fmt.Errorf("data too large")
	}
	lengthBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lengthBytes, uint16(length))
	frame := bytes.Buffer{}
	frame.Write(header)
	frame.Write(lengthBytes)
	frame.Write(b)
	_, err := c.tlsConn.Write(frame.Bytes())
	log.DebugDumpHex(frame.Bytes())

	return length, err
}

func (c *atrustConn) Close() error {
	closeMsg := []byte{0x01, 0x01, 0x00, 0x00}
	_, _ = c.tlsConn.Write(closeMsg)
	log.DebugPrint("Sent close message")
	log.DebugDumpHex(closeMsg)
	return c.tlsConn.Close()
}

func (c *atrustConn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *atrustConn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *atrustConn) SetDeadline(t time.Time) error {
	return c.tlsConn.SetDeadline(t)
}

func (c *atrustConn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}

func (c *atrustConn) SetWriteDeadline(t time.Time) error {
	return c.tlsConn.SetWriteDeadline(t)
}

func randUint64() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return fmt.Sprint(binary.BigEndian.Uint64(b[:]))
}

func calcXRequestSig(key []byte, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	sum := h.Sum(nil)
	return strings.ToUpper(hex.EncodeToString(sum))
}

func (s *Stack) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	appID := ""
	nodeGroupID := ""
	domain := ""
	if res := ctx.Value(resolve.ContextKeyDomainResource); res != nil {
		resource := res.(client.DomainResource)
		appID = resource.AppID
		nodeGroupID = resource.NodeGroupID
		if res = ctx.Value(resolve.ContextKeyResolveHost); res != nil {
			domain = res.(string)
		}
	} else {
		for _, resource := range s.ipResources {
			if bytes.Compare(addr.IP, resource.IPMin) >= 0 && bytes.Compare(addr.IP, resource.IPMax) <= 0 {
				if resource.PortMin <= addr.Port && addr.Port <= resource.PortMax {
					if resource.Protocol == "tcp" || resource.Protocol == "all" {
						appID = resource.AppID
						nodeGroupID = resource.NodeGroupID
					}
				}
			}
		}
	}

	s.bestNodesRWMutex.RLock()
	conn, err := tls.Dial("tcp", s.bestNodes[nodeGroupID], &tls.Config{
		InsecureSkipVerify: true,
	})
	s.bestNodesRWMutex.RUnlock()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aTrust server: %w", err)
	}

	connectionId := s.connectID + "-" + randUint64()
	procName := "curl"
	procPath := "/usr/bin/curl"
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

	destAddr := addr.String()
	if domain != "" {
		destAddr = fmt.Sprintf("%s:%d", domain, addr.Port)
	}

	destIP := addr.IP.To4()
	if destIP == nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	destPort := make([]byte, 2)
	binary.BigEndian.PutUint16(destPort, uint16(addr.Port))

	msg := fmt.Sprintf(
		`{"sid":"%s","appId":"%s","url":"tcp://%s","deviceId":"%s","connectionId":"%s","procHash":"%s","userName":"%s","rcAppliedInfo":0,"lang":"en-US","destAddr":"%s","env":{"application":{"runtime":{"process":{"name":"%s","digital_signature":"TrustAppClosed","platform":"Linux","fingerprint":"%s","description":"TrustAppClosed","path":"%s","version":"TrustAppClosed","security_env":"normal"},"process_trusted":"TRUSTED"}}},"xRequestSig":""}`,
		s.sid, appID, destAddr, s.deviceID, connectionId, procHash, s.username, destAddr, procName, procHash, procPath,
	)
	signKeyBytes, err := hex.DecodeString(s.signKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}

	sig := calcXRequestSig(signKeyBytes, []byte(msg))
	msg = msg[:len(msg)-3] + `"` + sig + `"}`
	msgBytes := []byte(msg)
	msgLen := len(msgBytes)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(msgLen))
	initHeader := []byte{0x05, 0x01, 0x81, 0x53, 0x03}
	initMsg := append(initHeader, lenBytes...)
	initMsg = append(initMsg, msgBytes...)
	if _, err := conn.Write(initMsg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send init message: %w", err)
	}
	log.DebugDumpHex(initMsg)

	var destMsg []byte
	if domain == "" {
		destHeader := []byte{0x05, 0x01, 0x01, 0x01}
		destMsg = append(destHeader, destIP...)
	} else {
		destHeader := []byte{0x05, 0x01, 0x01, 0x03}
		// For domain, we need to send the length of the domain name
		domainLen := len(domain)
		if domainLen > 255 {
			_ = conn.Close()
			return nil, fmt.Errorf("domain name too long: %s", domain)
		}
		destHeader = append(destHeader, byte(domainLen))
		destMsg = append(destHeader, []byte(domain)...)
	}
	destMsg = append(destMsg, destPort...)
	if _, err := conn.Write(destMsg); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to send dest address: %w", err)
	}
	log.DebugDumpHex(destMsg)

	return &atrustConn{
		tlsConn: conn,
		reader:  bufio.NewReader(conn),
	}, nil
}

func (s *Stack) DialUDP(ctx context.Context, addr *net.UDPAddr) (net.Conn, error) {
	return nil, fmt.Errorf("not implemented")
}
