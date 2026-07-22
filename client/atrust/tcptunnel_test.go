package atrust

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
)

func runTCPConnectExchange(t *testing.T, status byte) (error, []byte) {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	probeCh := make(chan []byte, 1)
	serverErrCh := make(chan error, 1)
	go func() {
		setupResponse := []byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x02, 'O', 'K'}
		for _, value := range setupResponse {
			if _, err := server.Write([]byte{value}); err != nil {
				serverErrCh <- err
				return
			}
		}

		probe := make([]byte, 4)
		if _, err := io.ReadFull(server, probe); err != nil {
			serverErrCh <- err
			return
		}
		probeCh <- probe
		_, err := server.Write([]byte{0x05, status})
		serverErrCh <- err
	}()

	err := waitForTCPConnect(context.Background(), client, bufio.NewReader(client))
	probe := <-probeCh
	if serverErr := <-serverErrCh; serverErr != nil {
		t.Fatalf("server exchange failed: %v", serverErr)
	}
	return err, probe
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
			err, probe := runTCPConnectExchange(t, test.status)
			if string(probe) != string([]byte{0x01, 0x00, 0x00, 0x00}) {
				t.Fatalf("unexpected connect probe: % X", probe)
			}
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

type signalingReader struct {
	io.Reader
	once    sync.Once
	started chan struct{}
}

func (r *signalingReader) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.started) })
	return r.Reader.Read(p)
}

func TestWaitForTCPConnectHonorsContextCancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	started := make(chan struct{})
	reader := bufio.NewReader(&signalingReader{Reader: client, started: started})
	ctx, cancel := context.WithCancel(context.Background())
	resultCh := make(chan error, 1)
	go func() {
		resultCh <- waitForTCPConnect(ctx, client, reader)
	}()

	<-started
	cancel()
	if err := <-resultCh; !errors.Is(err, context.Canceled) {
		t.Fatalf("waitForTCPConnect() error = %v, want context.Canceled", err)
	}
}

func TestWaitForTCPConnectRejectsMalformedResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	go func() {
		_, _ = server.Write([]byte{0x01, 0x00})
	}()

	err := waitForTCPConnect(context.Background(), client, bufio.NewReader(client))
	if err == nil || !strings.Contains(err.Error(), "unexpected tcp tunnel response: 01 00") {
		t.Fatalf("waitForTCPConnect() error = %v", err)
	}
}
