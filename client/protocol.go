package client

import (
	"crypto/rand"
	"errors"
	"github.com/mythologyli/zju-connect/log"
	"github.com/refraction-networking/utls"
	"io"
	"net"
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
func (c *EasyConnectClient) tlsConn() (*tls.UConn, error) {
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
	conn.HandshakeState.Hello.CompressionMethods = []uint8{1, 0}
	conn.HandshakeState.Hello.SessionId = []byte{'L', '3', 'I', 'P', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	conn.Extensions = []tls.TLSExtension{&fakeHeartBeatExtension{}}

	log.Println("TLS: connected to:", conn.RemoteAddr())

	return conn, nil
}

// RecvConn create a special TLS connection to receive data from the VPN server
func (c *EasyConnectClient) RecvConn() (*tls.UConn, error) {
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

// SendConn create a special TLS connection to send data to the VPN server
func (c *EasyConnectClient) SendConn() (*tls.UConn, error) {
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
		return nil, err
	}
	log.DebugPrintf("Send handshake: wrote %d bytes", n)
	log.DebugDumpHex(message[:n])

	reply := make([]byte, 1500)
	n, err = conn.Read(reply)
	if err != nil {
		return nil, err
	}
	log.DebugPrintf("Send handshake: read %d bytes", n)
	log.DebugDumpHex(reply[:n])

	if reply[0] != 0x02 {
		return nil, errors.New("unexpected send handshake reply")
	}

	return conn, err
}
