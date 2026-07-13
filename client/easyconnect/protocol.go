package easyconnect

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"

	"github.com/mythologyli/zju-connect/log"
	"github.com/refraction-networking/utls"
)

// Sentinel errors representing semantically-meaningful sangfor cmd codes
// returned by the server in response to a SendConn handshake. Identified
// via reverse engineering of svpnservice's HandCmdMsg dispatch table
// (jumptable @ 0x4e6fd0 in the official Linux EasyConnect 7.6.7 binary).
var (
	// 0x08 = SHUTDOWN — server is actively terminating this session and
	// will not accept retries with the same credentials. Equivalent to a
	// permanent "no" from the server. Recovery requires a fresh full
	// re-login (new TwfID + new token), or accepting the session is dead.
	ErrSangforShutdown = errors.New("sangfor: SHUTDOWN (cmd 0x08)")

	// 0x05/0x06/0x07/0x09 = RECONNECTLATER_* — server is busy or has a
	// session conflict. Caller should sleep and retry, optionally with
	// a fresh re-login. Official client surfaces this to its orchestrator
	// where an `enableAutoRelogin` config decides whether to redo the
	// /por/login_*.csp flow.
	ErrSangforReconnectLater = errors.New("sangfor: RECONNECT_LATER (cmd 0x05/0x06/0x07/0x09)")
)

type fakeHeartBeatExtension struct {
	*tls.GenericExtension
}

func (e *fakeHeartBeatExtension) Len() int {
	return 5
}

func (e *fakeHeartBeatExtension) Read(b []byte) (n int, err error) {
	if len(b) < e.Len() {
		return 0, io.ErrShortBuffer
	}
	b[1] = 0x0f
	b[3] = 1
	b[4] = 1

	return e.Len(), io.EOF
}

// Create a special TLS connection to the VPN server
func (c *Client) tlsConn() (*tls.UConn, error) {
	// Dial the VPN server
	dialConn, err := net.Dial("tcp", c.server)
	if err != nil {
		return nil, err
	}
	log.Println("Socket: connected to:", dialConn.RemoteAddr())

	// Use uTLS to construct a weird TLS Client Hello (required by Sangfor)
	// The VPN and HTTP Server share port 443, Sangfor uses a special SessionID to distinguish them
	conn := tls.UClient(dialConn, &tls.Config{InsecureSkipVerify: true}, tls.HelloCustom)

	random := make([]byte, 32)
	_, _ = rand.Read(random) // Ignore err
	_ = conn.SetClientRandom(random)
	_ = conn.SetTLSVers(tls.VersionTLS11, tls.VersionTLS11, []tls.TLSExtension{})
	conn.HandshakeState.Hello.Vers = tls.VersionTLS11
	conn.HandshakeState.Hello.CipherSuites = []uint16{tls.TLS_RSA_WITH_RC4_128_SHA, tls.FAKE_TLS_EMPTY_RENEGOTIATION_INFO_SCSV}
	conn.HandshakeState.Hello.CompressionMethods = []uint8{0}
	conn.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	conn.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}

	log.Println("TLS: connected to:", conn.RemoteAddr())

	return conn, nil
}

// RecvConn create a special TLS connection to receive data from the VPN server
func (c *Client) RecvConn() (*tls.UConn, error) {
	if c.token == nil {
		return nil, errors.New("token is nil")
	}

	conn, err := c.tlsConn()
	if err != nil {
		return nil, err
	}

	// RECV STREAM START
	message := []byte{0x06, 0x00, 0x00, 0x00}
	message = append(message, c.token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, c.ipReverse[:]...)

	n, err := conn.Write(message)
	if err != nil {
		return nil, err
	}
	log.DebugPrintf("Recv handshake: wrote %d bytes", n)
	log.DebugDumpHex(message[:n])

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		return nil, err
	}
	log.DebugPrintf("Recv handshake: read %d bytes", n)
	log.DebugDumpHex(reply[:n])

	if reply[0] != 0x01 {
		return nil, errors.New("unexpected recv handshake reply")
	}

	return conn, nil
}

// SendConn create a special TLS connection to send data to the VPN server.
//
// The first byte of the server reply is a HandCmdMsg cmd code, dispatched
// by upstream sangfor's svpnservice. Known values:
//
//	0x00 = SEND_IP  (zju-connect protocol uses 0x02 here as its OK marker;
//	                 the relationship between 0x02 and the full sangfor
//	                 cmd table isn't fully understood, but accepting it
//	                 has worked reliably for years)
//	0x05/0x06/0x07/0x09 = RECONNECTLATER_*
//	0x08 = SHUTDOWN
//	0x0a = IPVALID
//	0x0e/0x0f = HEARTBEAT
//
// Anything other than the legacy 0x02 success marker is converted into a
// typed error so the caller can decide policy (retry / re-login / exit).
func (c *Client) SendConn() (*tls.UConn, error) {
	if c.token == nil {
		return nil, errors.New("token is nil")
	}

	conn, err := c.tlsConn()
	if err != nil {
		return nil, err
	}

	// SEND STREAM START
	message := []byte{0x05, 0x00, 0x00, 0x00}
	message = append(message, c.token[:]...)
	message = append(message, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
	message = append(message, c.ipReverse[:]...)

	n, err := conn.Write(message)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	log.DebugPrintf("Send handshake: wrote %d bytes", n)
	log.DebugDumpHex(message[:n])

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	log.DebugPrintf("Send handshake: read %d bytes", n)
	log.DebugDumpHex(reply[:n])

	switch reply[0] {
	case 0x02:
		return conn, nil
	case 0x08:
		_ = conn.Close()
		log.Printf("SendConn: server returned SHUTDOWN (cmd 0x08); session terminated by server")
		return nil, ErrSangforShutdown
	case 0x05, 0x06, 0x07, 0x09:
		_ = conn.Close()
		log.Printf("SendConn: server returned RECONNECTLATER (cmd 0x%02x); should re-login and retry", reply[0])
		return nil, ErrSangforReconnectLater
	default:
		_ = conn.Close()
		return nil, fmt.Errorf("unexpected send handshake reply: 0x%02x", reply[0])
	}
}
