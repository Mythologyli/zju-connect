package atrust

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/resolve"
)

type tcpTunnelConn struct {
	tlsConn net.Conn
	reader  *bufio.Reader
	readMu  sync.Mutex
	writeMu sync.Mutex
	readBuf []byte
	reuse   bool
	raw     bool

	closeWriteOnce sync.Once
	closeWriteErr  error
}

const tcpTunnelHandshakeTimeout = 18 * time.Second

func tcpTunnelHandshakeDeadline(ctx context.Context, now time.Time) time.Time {
	deadline := now.Add(tcpTunnelHandshakeTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		return ctxDeadline
	}
	return deadline
}

func readTCPProtocolResponse(reader *bufio.Reader) (string, error) {
	lengthBytes := make([]byte, 2)
	if _, err := io.ReadFull(reader, lengthBytes); err != nil {
		return "", err
	}
	data := make([]byte, binary.BigEndian.Uint16(lengthBytes))
	if _, err := io.ReadFull(reader, data); err != nil {
		return "", err
	}
	return string(data), nil
}

type tcpTunnelAuthResponse struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

type tcpTunnelProcess struct {
	Name             string `json:"name"`
	DigitalSignature string `json:"digital_signature"`
	Platform         string `json:"platform"`
	Fingerprint      string `json:"fingerprint"`
	Description      string `json:"description"`
	Path             string `json:"path"`
	Version          string `json:"version"`
	SecurityEnv      string `json:"security_env"`
}

type tcpTunnelAuthRequest struct {
	SID           string `json:"sid"`
	AppID         string `json:"appId"`
	URL           string `json:"url"`
	DeviceID      string `json:"deviceId"`
	ConnectionID  string `json:"connectionId"`
	ProcHash      string `json:"procHash"`
	UserName      string `json:"userName"`
	RCAppliedInfo int    `json:"rcAppliedInfo"`
	Lang          string `json:"lang"`
	DestAddr      string `json:"destAddr"`
	DestIP        string `json:"destIP,omitempty"`
	Env           struct {
		Application struct {
			Runtime struct {
				Process        tcpTunnelProcess `json:"process"`
				ProcessTrusted string           `json:"process_trusted"`
			} `json:"runtime"`
		} `json:"application"`
	} `json:"env"`
	XRequestSig string `json:"xRequestSig"`
}

func marshalTCPTunnelAuthRequest(request tcpTunnelAuthRequest, signKey []byte) ([]byte, error) {
	unsigned, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tcp tunnel auth request: %w", err)
	}
	request.XRequestSig = calcXRequestSig(signKey, unsigned)
	signed, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal signed tcp tunnel auth request: %w", err)
	}
	return signed, nil
}

func encodeTCPTunnelAuthLength(length int) ([2]byte, error) {
	var encoded [2]byte
	if length > 0xFFFF {
		return encoded, fmt.Errorf("tcp tunnel auth request too large: %d bytes", length)
	}
	binary.BigEndian.PutUint16(encoded[:], uint16(length))
	return encoded, nil
}

func writeTCPTunnelHandshakeMessage(writer io.Writer, data []byte) error {
	n, err := writer.Write(data)
	if err != nil {
		return err
	}
	if n != len(data) {
		return io.ErrShortWrite
	}
	return nil
}

func writeTCPTunnelInitialMessages(writer io.Writer, initMsg, destMsg []byte, zeroRTT bool) error {
	if err := writeTCPTunnelHandshakeMessage(writer, initMsg); err != nil {
		return fmt.Errorf("failed to send init message: %w", err)
	}
	if zeroRTT {
		if err := writeTCPTunnelHandshakeMessage(writer, destMsg); err != nil {
			return fmt.Errorf("failed to send dest address: %w", err)
		}
	}
	return nil
}

func encodeTCPTunnelDestination(destIP net.IP, port int, zeroRTT bool) ([]byte, error) {
	ipv4 := destIP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("invalid IPv4 address")
	}
	rsv := byte(0)
	if zeroRTT {
		rsv = 1
	}
	msg := append([]byte{0x05, 0x01, rsv, 0x01}, ipv4...)
	return binary.BigEndian.AppendUint16(msg, uint16(port)), nil
}

func parseTCPTunnelAuthResponse(data string) error {
	var response tcpTunnelAuthResponse
	if err := json.Unmarshal([]byte(data), &response); err != nil {
		return fmt.Errorf("failed to parse tcp tunnel auth response: %w", err)
	}
	if response.Code != 0 {
		return fmt.Errorf("tcp tunnel authentication failed (code %d): %s", response.Code, response.Message)
	}
	return nil
}

func readSOCKS5ConnectReply(reader *bufio.Reader) (status byte, reuse bool, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return 0, false, fmt.Errorf("failed to read tcp tunnel connect reply: %w", err)
	}
	if header[0] != 0x05 {
		return 0, false, fmt.Errorf("unexpected tcp tunnel connect version: 0x%02X", header[0])
	}
	if header[1] != 0x00 {
		return header[1], false, nil
	}
	var addressLength int
	switch header[3] {
	case 0x01:
		addressLength = net.IPv4len
	case 0x04:
		addressLength = net.IPv6len
	default:
		return 0, false, fmt.Errorf("unexpected tcp tunnel bind address type: 0x%02X", header[3])
	}
	if _, err := io.CopyN(io.Discard, reader, int64(addressLength+2)); err != nil {
		return 0, false, fmt.Errorf("failed to read tcp tunnel bind address: %w", err)
	}
	return 0, header[2] == 0x01, nil
}

func waitForTCPConnect(ctx context.Context, conn net.Conn, reader *bufio.Reader) (err error) {
	_, err = waitForTCPConnectReply(ctx, conn, reader)
	return err
}

func waitForTCPAuth(ctx context.Context, conn net.Conn, reader *bufio.Reader) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}

	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		defer close(cancelDone)
		_ = conn.Close()
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
	}()

	header := make([]byte, 2)
	if _, err := io.ReadFull(reader, header); err != nil {
		return fmt.Errorf("failed to read tcp tunnel response: %w", err)
	}
	if header[0] != 0x53 || header[1] != 0x00 {
		return fmt.Errorf("unexpected tcp tunnel response: %02X %02X", header[0], header[1])
	}
	response, err := readTCPProtocolResponse(reader)
	if err != nil {
		return fmt.Errorf("failed to read tcp tunnel protocol response: %w", err)
	}
	log.DebugPrint("Received protocol response:")
	log.DebugDumpHex([]byte(response))
	return parseTCPTunnelAuthResponse(response)
}

func waitForTCPConnectReply(ctx context.Context, conn net.Conn, reader *bufio.Reader) (reuse bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}

	cancelDone := make(chan struct{})
	stopCancel := context.AfterFunc(ctx, func() {
		defer close(cancelDone)
		_ = conn.Close()
	})
	defer func() {
		if !stopCancel() {
			<-cancelDone
		}
		if ctxErr := ctx.Err(); ctxErr != nil {
			err = ctxErr
		}
	}()

	for {
		header := make([]byte, 2)
		if _, err := io.ReadFull(reader, header); err != nil {
			return false, fmt.Errorf("failed to read tcp tunnel response: %w", err)
		}
		if log.DebugEnabled() {
			log.DebugPrintf("Received header: %02X %02X", header[0], header[1])
		}
		if header[0] == 0x05 && header[1] == 0x81 {
			continue
		}
		if header[0] != 0x53 || header[1] != 0x00 {
			return false, fmt.Errorf("unexpected tcp tunnel response: %02X %02X", header[0], header[1])
		}

		response, err := readTCPProtocolResponse(reader)
		if err != nil {
			return false, fmt.Errorf("failed to read tcp tunnel protocol response: %w", err)
		}
		log.DebugPrint("Received protocol response:")
		log.DebugDumpHex([]byte(response))
		if err := parseTCPTunnelAuthResponse(response); err != nil {
			return false, err
		}
		break
	}

	status, reuse, err := readSOCKS5ConnectReply(reader)
	if err != nil {
		return false, err
	}
	if log.DebugEnabled() {
		log.DebugPrintf("Received TCP connect status: 0x%02X", status)
	}

	switch status {
	case 0x00:
		return reuse, nil
	case 0x01:
		return false, fmt.Errorf("tcp tunnel server failure")
	case 0x02:
		return false, fmt.Errorf("tcp tunnel connection not allowed")
	case 0x03:
		return false, fmt.Errorf("network is unreachable")
	case 0x04:
		return false, fmt.Errorf("host is unreachable")
	case 0x05:
		return false, fmt.Errorf("connection refused")
	case 0x06:
		return false, fmt.Errorf("tcp tunnel TTL expired")
	case 0x07:
		return false, fmt.Errorf("tcp tunnel command not supported")
	case 0x08:
		return false, fmt.Errorf("tcp tunnel address type not supported")
	default:
		return false, fmt.Errorf("tcp tunnel connect failed with status 0x%02X", status)
	}
}

func (c *tcpTunnelConn) Read(b []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	if len(b) == 0 {
		return 0, nil
	}
	if c.raw {
		return c.reader.Read(b)
	}
	if len(c.readBuf) > 0 {
		n := copy(b, c.readBuf)
		c.readBuf = c.readBuf[n:]
		return n, nil
	}

	for {
		var header [4]byte
		if _, err := io.ReadFull(c.reader, header[:]); err != nil {
			log.DebugPrintf("TCP tunnel read ended: %v", err)
			return 0, err
		}
		switch {
		case header[0] == 0x01 && header[1] == 0x00:
			length := int(binary.BigEndian.Uint16(header[2:]))
			if length == 0 {
				continue
			}
			if length <= len(b) {
				if _, err := io.ReadFull(c.reader, b[:length]); err != nil {
					return 0, err
				}
				log.DebugPrintf("TCP tunnel received %d bytes", length)
				log.DebugDumpHex(b[:length])
				return length, nil
			}

			payload := make([]byte, length)
			if _, err := io.ReadFull(c.reader, payload); err != nil {
				return 0, err
			}
			log.DebugPrintf("TCP tunnel received %d bytes", length)
			log.DebugDumpHex(payload)
			n := copy(b, payload)
			c.readBuf = payload[n:]
			return n, nil
		case header[0] == 0x01 && header[1] == 0x01:
			log.DebugPrint("TCP tunnel closed by server")
			return 0, io.EOF
		default:
			return 0, fmt.Errorf("unexpected TCP tunnel data frame header: % x", header)
		}
	}
}

func (c *tcpTunnelConn) Write(b []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if len(b) == 0 {
		return 0, nil
	}
	if c.raw {
		return c.tlsConn.Write(b)
	}

	written := 0
	for written < len(b) {
		chunkSize := min(len(b)-written, 0xFFFF)
		chunk := b[written : written+chunkSize]
		frame := make([]byte, 4+chunkSize)
		frame[0] = 0x01
		binary.BigEndian.PutUint16(frame[2:4], uint16(chunkSize))
		copy(frame[4:], chunk)
		if err := writeTCPTunnelHandshakeMessage(c.tlsConn, frame); err != nil {
			log.DebugPrintf("TCP tunnel write failed after %d bytes: %v", written, err)
			return written, err
		}
		written += chunkSize
	}
	log.DebugPrintf("TCP tunnel sent %d bytes", written)
	log.DebugDumpHex(b)
	return written, nil
}

func (c *tcpTunnelConn) Close() error {
	writeErr := c.CloseWrite()
	closeErr := c.tlsConn.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func (c *tcpTunnelConn) CloseRead() error {
	if conn, ok := c.tlsConn.(interface{ CloseRead() error }); ok {
		return conn.CloseRead()
	}
	return nil
}

func (c *tcpTunnelConn) CloseWrite() error {
	c.closeWriteOnce.Do(func() {
		c.writeMu.Lock()
		defer c.writeMu.Unlock()
		if c.reuse {
			c.closeWriteErr = writeTCPTunnelHandshakeMessage(c.tlsConn, []byte{0x01, 0x01, 0x00, 0x00})
			return
		}
		if conn, ok := c.tlsConn.(interface{ CloseWrite() error }); ok {
			c.closeWriteErr = conn.CloseWrite()
		}
	})
	return c.closeWriteErr
}

func (c *tcpTunnelConn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *tcpTunnelConn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *tcpTunnelConn) SetDeadline(t time.Time) error {
	return c.tlsConn.SetDeadline(t)
}

func (c *tcpTunnelConn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}

func (c *tcpTunnelConn) SetWriteDeadline(t time.Time) error {
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

func matchTCPIPResource(index *ipresource.Index, addr *net.TCPAddr) (client.IPResource, bool) {
	return index.MatchLast(addr.IP, "tcp", addr.Port)
}

func tcpTunnelAuthDestinations(addr *net.TCPAddr, domain string) (destAddr, destIP string) {
	destAddr = addr.String()
	if domain != "" {
		destAddr = fmt.Sprintf("%s:%d", domain, addr.Port)
		destIP = addr.IP.String()
	}
	return destAddr, destIP
}

func (c *Client) DialTCP(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	appID := ""
	nodeGroupID := ""
	domain := ""
	if resource, ok := ctx.Value(resolve.ContextKeyDomainResource).(client.DomainResource); ok {
		appID = resource.AppID
		nodeGroupID = resource.NodeGroupID
		if res := ctx.Value(resolve.ContextKeyResolveHost); res != nil {
			domain = res.(string)
		}
	}
	if appID == "" {
		resource, ok := matchTCPIPResource(c.resourceIndex, addr)
		if ok {
			appID = resource.AppID
			nodeGroupID = resource.NodeGroupID
			domain = ""
		}
	}
	if appID == "" {
		return nil, fmt.Errorf("host:%s port:%d is not resource: %w", addr.IP, addr.Port, client.ErrResourceNotFound)
	}

	c.BestNodesRWMutex.RLock()
	nodeAddr := c.BestNodes[nodeGroupID]
	if nodeAddr == "" {
		nodeAddr = c.BestNodes[c.MajorNodeGroup]
	}
	c.BestNodesRWMutex.RUnlock()
	if nodeAddr == "" {
		return nil, fmt.Errorf("no available aTrust node for group %q", nodeGroupID)
	}
	conn, err := c.underlayDialer.DialTLSContext(ctx, "tcp", nodeAddr, tunnelTLSConfig())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to aTrust server: %w", err)
	}
	if err := conn.SetReadDeadline(tcpTunnelHandshakeDeadline(ctx, time.Now())); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to set tcp tunnel handshake timeout: %w", err)
	}
	procName := "google-chrome-stable"
	procPath := "/usr/bin/google-chrome-stable"
	if addr.Port == 22 {
		procName = "ssh"
		procPath = "/usr/bin/ssh"
	}
	procHash := fmt.Sprintf("%X", sha256.Sum256([]byte(procPath)))

	destAddr, destIP := tcpTunnelAuthDestinations(addr, domain)

	signKeyBytes, err := hex.DecodeString(c.SignKey)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("invalid sign key: %w", err)
	}
	authRequest := tcpTunnelAuthRequest{
		SID:          c.SID,
		AppID:        appID,
		URL:          "tcp://" + destAddr,
		DeviceID:     c.DeviceID,
		ConnectionID: c.ConnectionID,
		ProcHash:     procHash,
		UserName:     c.Username,
		Lang:         "en-US",
		DestAddr:     destAddr,
		DestIP:       destIP,
		XRequestSig:  "",
	}
	authRequest.Env.Application.Runtime.Process = tcpTunnelProcess{
		Name:             procName,
		DigitalSignature: "TrustAppClosed",
		Platform:         "Linux",
		Fingerprint:      procHash,
		Description:      "TrustAppClosed",
		Path:             procPath,
		Version:          "TrustAppClosed",
		SecurityEnv:      "normal",
	}
	authRequest.Env.Application.Runtime.ProcessTrusted = "TRUSTED"
	msgBytes, err := marshalTCPTunnelAuthRequest(authRequest, signKeyBytes)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	lenBytes, err := encodeTCPTunnelAuthLength(len(msgBytes))
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	initHeader := []byte{0x05, 0x01, 0x81, 0x53, 0x03}
	initMsg := append(initHeader, lenBytes[:]...)
	initMsg = append(initMsg, msgBytes...)
	destMsg, err := encodeTCPTunnelDestination(addr.IP, addr.Port, c.tcpTunnelZeroRTT)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if err := writeTCPTunnelInitialMessages(conn, initMsg, destMsg, c.tcpTunnelZeroRTT); err != nil {
		_ = conn.Close()
		return nil, err
	}
	log.DebugDumpHex(initMsg)
	if c.tcpTunnelZeroRTT {
		log.DebugDumpHex(destMsg)
	}

	tunnelConn := &tcpTunnelConn{
		tlsConn: conn,
		reader:  bufio.NewReader(conn),
		raw:     !c.tcpTunnelZeroRTT,
	}
	var reuse bool
	var waitErr error
	if c.tcpTunnelZeroRTT {
		reuse, waitErr = waitForTCPConnectReply(ctx, conn, tunnelConn.reader)
	} else {
		waitErr = waitForTCPAuth(ctx, conn, tunnelConn.reader)
	}
	clearDeadlineErr := conn.SetReadDeadline(time.Time{})
	if waitErr != nil {
		_ = conn.Close()
		return nil, waitErr
	}
	if clearDeadlineErr != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("failed to clear tcp tunnel handshake timeout: %w", clearDeadlineErr)
	}
	tunnelConn.reuse = reuse
	return tunnelConn, nil
}
