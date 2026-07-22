package atrust

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
)

var tcpSetupResponse = []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x02, 'O', 'K'}

func runTCPConnectExchange(status byte) error {
	response := append([]byte{}, tcpSetupResponse...)
	response = append(response, 0x05, status, 0x00, 0x01)
	if status == 0x00 {
		response = append(response, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	}
	return waitForTCPConnect(bufio.NewReader(bytes.NewReader(response)))
}

func TestWaitForTCPConnectStatus(t *testing.T) {
	tests := []struct {
		name       string
		status     byte
		wantErrMsg string
	}{
		{name: "connected", status: 0x00},
		{name: "server failure", status: 0x01, wantErrMsg: "tcp tunnel server failure"},
		{name: "not allowed", status: 0x02, wantErrMsg: "tcp tunnel connection not allowed"},
		{name: "network unreachable", status: 0x03, wantErrMsg: "network is unreachable"},
		{name: "host unreachable", status: 0x04, wantErrMsg: "host is unreachable"},
		{name: "refused", status: 0x05, wantErrMsg: "connection refused"},
		{name: "TTL expired", status: 0x06, wantErrMsg: "tcp tunnel TTL expired"},
		{name: "command unsupported", status: 0x07, wantErrMsg: "tcp tunnel command not supported"},
		{name: "address type unsupported", status: 0x08, wantErrMsg: "tcp tunnel address type not supported"},
		{name: "unknown", status: 0xff, wantErrMsg: "tcp tunnel connect failed with status 0xFF"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runTCPConnectExchange(test.status)
			if test.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("waitForTCPConnect() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrMsg) {
				t.Fatalf("waitForTCPConnect() error = %v, want message %q", err, test.wantErrMsg)
			}
		})
	}
}

func TestReadTCPConnectStatusSuccessReplies(t *testing.T) {
	tests := []struct {
		name  string
		reply []byte
	}{
		{name: "IPv4", reply: []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90}},
		{name: "domain", reply: []byte{0x05, 0x00, 0x00, 0x03, 0x03, 'z', 'j', 'u', 0x01, 0xbb}},
		{name: "IPv6", reply: []byte{0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			status, err := readTCPConnectStatus(bufio.NewReader(bytes.NewReader(test.reply)))
			if err != nil {
				t.Fatalf("readTCPConnectStatus() error = %v", err)
			}
			if status != 0x00 {
				t.Fatalf("readTCPConnectStatus() status = 0x%02X", status)
			}
		})
	}
}

func TestEstablishTCPConnectionHonorsContextCancellation(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	request := []byte{0x05, 0x01, 0x81, 0x05, 0x01, 0x01}
	requestRead := make(chan struct{})
	go func() {
		_, _ = io.ReadFull(serverConn, make([]byte, len(request)))
		close(requestRead)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	client := &Client{}
	go func() {
		resultCh <- client.establishTCPConnection(ctx, clientConn, bufio.NewReader(clientConn), request)
	}()

	<-requestRead
	cancel()
	if err := <-resultCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("establishTCPConnection() error = %v, want context.Canceled", err)
	}
}

func TestWaitForTCPConnectRejectsMalformedResponse(t *testing.T) {
	err := waitForTCPConnect(bufio.NewReader(bytes.NewReader([]byte{0x01, 0x00})))
	if err == nil || !strings.Contains(err.Error(), "unexpected tcp tunnel response: 01 00") {
		t.Fatalf("waitForTCPConnect() error = %v", err)
	}
}

func TestEstablishTCPConnectionCanSkipWait(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	request := []byte{0x05, 0x01, 0x81, 0x05, 0x01, 0x01}
	requestCh := make(chan []byte, 1)
	go func() {
		got := make([]byte, len(request))
		_, _ = io.ReadFull(serverConn, got)
		requestCh <- got
	}()

	client := &Client{skipTCPTunnelWait: true}
	if err := client.establishTCPConnection(context.Background(), clientConn, bufio.NewReader(clientConn), request); err != nil {
		t.Fatalf("establishTCPConnection() error = %v", err)
	}
	if got := <-requestCh; !bytes.Equal(got, request) {
		t.Fatalf("request = % X, want % X", got, request)
	}
}
