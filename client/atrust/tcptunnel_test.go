package atrust

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client"
	"github.com/mythologyli/zju-connect/internal/ipresource"
)

func TestTCPTunnelReadDecodesDownstreamFramesAcrossBufferSizes(t *testing.T) {
	for _, bufferSize := range []int{2, 5, 16} {
		t.Run(fmt.Sprintf("buffer_%d", bufferSize), func(t *testing.T) {
			payload := []byte("hello")
			frame := append([]byte{0x01, 0x00, 0x00, byte(len(payload))}, payload...)
			conn := &tcpTunnelConn{reader: bufio.NewReader(bytes.NewReader(frame))}
			var got []byte
			buf := make([]byte, bufferSize)
			for len(got) < len(payload) {
				n, err := conn.Read(buf)
				if err != nil {
					t.Fatalf("Read() error = %v", err)
				}
				got = append(got, buf[:n]...)
			}
			if !bytes.Equal(got, payload) {
				t.Fatalf("Read() payload = %q, want %q", got, payload)
			}
		})
	}
}

func TestTCPTunnelReadReturnsEOFForServerCloseFrame(t *testing.T) {
	for _, frame := range [][]byte{
		{0x01, 0x01, 0x00, 0x00},
		{0x01, 0x01, 0x30, 0x30},
		{0x01, 0x01, 0x12, 0x34},
	} {
		conn := &tcpTunnelConn{reader: bufio.NewReader(bytes.NewReader(frame))}
		if n, err := conn.Read(make([]byte, 16)); n != 0 || !errors.Is(err, io.EOF) {
			t.Fatalf("Read(% X) = (%d, %v), want (0, io.EOF)", frame, n, err)
		}
	}
}

func TestTCPTunnelReadEmptyDoesNotConsumeFrame(t *testing.T) {
	frame := []byte{0x01, 0x00, 0x00, 0x03, 'a', 'b', 'c'}
	conn := &tcpTunnelConn{reader: bufio.NewReader(bytes.NewReader(frame))}

	n, err := conn.Read(nil)
	if err != nil {
		t.Fatalf("Read(nil) error = %v", err)
	}
	if n != 0 {
		t.Fatalf("Read(nil) = %d, want 0", n)
	}

	buf := make([]byte, 3)
	n, err = conn.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != len(buf) || string(buf) != "abc" {
		t.Fatalf("Read() = %d, %q; want 3, %q", n, buf, "abc")
	}
}

func TestTCPTunnelReadRejectsUnknownFrame(t *testing.T) {
	conn := &tcpTunnelConn{reader: bufio.NewReader(bytes.NewReader([]byte{0x02, 0x00, 0x00, 0x00}))}
	if _, err := conn.Read(make([]byte, 16)); err == nil || !strings.Contains(err.Error(), "unexpected TCP tunnel data frame header") {
		t.Fatalf("Read() error = %v", err)
	}
}

func TestWaitForTCPConnectPreservesBufferedDownstreamData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("HTTP/1.1 200 OK\r\n")
	serverErrCh := make(chan error, 1)
	go func() {
		response := append([]byte{0x53, 0x00, 0x00, 0x21}, []byte(`{"code":0,"message":"Successful"}`)...)
		if _, err := server.Write(response); err != nil {
			serverErrCh <- err
			return
		}
		statusAndPayload := append([]byte{0x05, 0x00, 0x00, 0x01, 10, 0, 0, 1, 0x1F, 0x90, 0x01, 0x00, 0x00, byte(len(payload))}, payload...)
		_, err := server.Write(statusAndPayload)
		serverErrCh <- err
	}()

	reader := bufio.NewReader(client)
	if err := waitForTCPConnect(context.Background(), client, reader); err != nil {
		t.Fatalf("waitForTCPConnect() error = %v", err)
	}
	conn := &tcpTunnelConn{reader: reader}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("Read() payload = %q, want %q", got, payload)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("server exchange failed: %v", err)
	}
}

func TestReadSOCKS5ConnectReplyReturnsReuseFlag(t *testing.T) {
	reply := []byte{0x05, 0x00, 0x01, 0x01, 10, 249, 8, 102, 0x01, 0xBB}
	status, reuse, err := readSOCKS5ConnectReply(bufio.NewReader(bytes.NewReader(reply)))
	if err != nil {
		t.Fatalf("readSOCKS5ConnectReply() error = %v", err)
	}
	if status != 0x00 {
		t.Fatalf("readSOCKS5ConnectReply() status = 0x%02X, want 0x00", status)
	}
	if !reuse {
		t.Fatal("readSOCKS5ConnectReply() reuse = false, want true")
	}

	reply[2] = 0x00
	_, reuse, err = readSOCKS5ConnectReply(bufio.NewReader(bytes.NewReader(reply)))
	if err != nil {
		t.Fatalf("readSOCKS5ConnectReply(non-reuse) error = %v", err)
	}
	if reuse {
		t.Fatal("readSOCKS5ConnectReply() reuse = true, want false")
	}
}

func TestTCPTunnelWriteEncodesUpstreamFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	serverResult := make(chan []byte, 1)
	go func() {
		got := make([]byte, 4+len(payload))
		if _, err := io.ReadFull(server, got); err != nil {
			serverResult <- nil
			return
		}
		serverResult <- got
	}()

	conn := &tcpTunnelConn{tlsConn: client}
	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() length = %d, want %d", n, len(payload))
	}
	want := append([]byte{0x01, 0x00, 0x00, byte(len(payload))}, payload...)
	if got := <-serverResult; !bytes.Equal(got, want) {
		t.Fatalf("upstream frame = % X, want % X", got, want)
	}
}

func TestTCPTunnelWriteEmptyDoesNotSendFrame(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying}

	n, err := conn.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil) error = %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(nil) = %d, want 0", n)
	}
	if underlying.Len() != 0 {
		t.Fatalf("Write(nil) sent %d bytes, want none", underlying.Len())
	}
}

func TestTCPTunnelWriteSplitsOversizedPayload(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 0x10000)
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying}

	n, err := conn.Write(payload)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Write() = %d, want %d", n, len(payload))
	}

	encoded := underlying.Bytes()
	firstFrameSize := 4 + 0xFFFF
	if len(encoded) != firstFrameSize+5 {
		t.Fatalf("encoded length = %d, want %d", len(encoded), firstFrameSize+5)
	}
	if got := encoded[:4]; !bytes.Equal(got, []byte{0x01, 0x00, 0xFF, 0xFF}) {
		t.Fatalf("first frame header = % X", got)
	}
	if got := encoded[firstFrameSize : firstFrameSize+4]; !bytes.Equal(got, []byte{0x01, 0x00, 0x00, 0x01}) {
		t.Fatalf("second frame header = % X", got)
	}
	decoded := append([]byte(nil), encoded[4:firstFrameSize]...)
	decoded = append(decoded, encoded[firstFrameSize+4:]...)
	if !bytes.Equal(decoded, payload) {
		t.Fatal("split frames did not preserve payload")
	}
}

func TestTCPTunnelConcurrentWritesPreserveFrameBoundaries(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying}
	payloads := [][]byte{
		bytes.Repeat([]byte{'a'}, 0x10000),
		bytes.Repeat([]byte{'b'}, 0x10000),
	}

	var wg sync.WaitGroup
	for _, payload := range payloads {
		payload := payload
		wg.Add(1)
		go func() {
			defer wg.Done()
			if n, err := conn.Write(payload); err != nil || n != len(payload) {
				t.Errorf("Write() = %d, %v; want %d, nil", n, err, len(payload))
			}
		}()
	}
	wg.Wait()

	encoded := underlying.Bytes()
	var decoded []byte
	for len(encoded) > 0 {
		if len(encoded) < 4 || encoded[0] != 0x01 || encoded[1] != 0x00 {
			t.Fatal("invalid frame header")
		}
		length := int(binary.BigEndian.Uint16(encoded[2:4]))
		if len(encoded) < 4+length {
			t.Fatalf("truncated frame length %d", length)
		}
		decoded = append(decoded, encoded[4:4+length]...)
		encoded = encoded[4+length:]
	}
	wantAB := append(append([]byte(nil), payloads[0]...), payloads[1]...)
	wantBA := append(append([]byte(nil), payloads[1]...), payloads[0]...)
	if !bytes.Equal(decoded, wantAB) && !bytes.Equal(decoded, wantBA) {
		t.Fatal("concurrent writes were interleaved")
	}
}

type recordingConn struct {
	bytes.Buffer
	closed      bool
	readClosed  bool
	writeClosed bool
}

func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) Close() error                     { c.closed = true; return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return nil }
func (c *recordingConn) RemoteAddr() net.Addr             { return nil }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }
func (c *recordingConn) CloseRead() error                 { c.readClosed = true; return nil }
func (c *recordingConn) CloseWrite() error                { c.writeClosed = true; return nil }

func TestTCPTunnelCloseSendsCloseFrame(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying, reuse: true}

	if err := conn.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !underlying.closed {
		t.Fatal("Close() did not close the underlying connection")
	}
	if got, want := underlying.Bytes(), []byte{0x01, 0x01, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("Close() wrote % X, want % X", got, want)
	}
}

func TestTCPTunnelHalfCloseUsesProtocolFrame(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying, reuse: true}

	if err := conn.CloseRead(); err != nil {
		t.Fatalf("CloseRead() error = %v", err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if !underlying.readClosed || underlying.writeClosed {
		t.Fatalf("unexpected underlying half-close: read=%v write=%v", underlying.readClosed, underlying.writeClosed)
	}
	if got, want := underlying.Bytes(), []byte{0x01, 0x01, 0x00, 0x00}; !bytes.Equal(got, want) {
		t.Fatalf("CloseWrite() wrote % X, want % X", got, want)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite() error = %v", err)
	}
	if underlying.Len() != 4 {
		t.Fatalf("second CloseWrite() sent another frame: % X", underlying.Bytes())
	}
}

func TestTCPTunnelNonReuseHalfCloseUsesTransport(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{tlsConn: underlying}

	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite() error = %v", err)
	}
	if !underlying.writeClosed {
		t.Fatal("CloseWrite() did not half-close the non-reusable transport")
	}
	if underlying.Len() != 0 {
		t.Fatalf("CloseWrite() wrote a QConn close frame for non-reusable transport: % X", underlying.Bytes())
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("second CloseWrite() error = %v", err)
	}
}

func TestTCPTunnelHandshakeDeadlineUsesEarlierContextDeadline(t *testing.T) {
	now := time.Now()
	ctxDeadline := now.Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), ctxDeadline)
	defer cancel()

	if got := tcpTunnelHandshakeDeadline(ctx, now); !got.Equal(ctxDeadline) {
		t.Fatalf("handshake deadline = %v, want context deadline %v", got, ctxDeadline)
	}
	if got := tcpTunnelHandshakeDeadline(context.Background(), now); !got.Equal(now.Add(tcpTunnelHandshakeTimeout)) {
		t.Fatalf("handshake deadline = %v, want %v", got, now.Add(tcpTunnelHandshakeTimeout))
	}
}

func TestParseTCPTunnelAuthResponse(t *testing.T) {
	tests := []struct {
		name       string
		response   string
		wantErrMsg string
	}{
		{name: "success without OK message", response: `{"code":0,"message":"Successful"}`},
		{name: "failed response containing OK", response: `{"code":73600007,"message":"NOT OK"}`, wantErrMsg: "code 73600007"},
		{name: "malformed response", response: `{"code":`, wantErrMsg: "failed to parse"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := parseTCPTunnelAuthResponse(test.response)
			if test.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("parseTCPTunnelAuthResponse() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrMsg) {
				t.Fatalf("parseTCPTunnelAuthResponse() error = %v, want message %q", err, test.wantErrMsg)
			}
		})
	}
}

func TestMarshalTCPTunnelAuthRequestEscapesFieldsAndSignsUnsignedJSON(t *testing.T) {
	request := tcpTunnelAuthRequest{
		SID:         "sid",
		AppID:       "app",
		UserName:    "user\\\"name",
		DestIP:      "10.75.11.237",
		XRequestSig: "",
	}
	signKey := []byte("test-signing-key")
	data, err := marshalTCPTunnelAuthRequest(request, signKey)
	if err != nil {
		t.Fatalf("marshalTCPTunnelAuthRequest() error = %v", err)
	}

	var decoded tcpTunnelAuthRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("generated auth request is invalid JSON: %v", err)
	}
	if decoded.UserName != request.UserName {
		t.Fatalf("decoded username = %q, want %q", decoded.UserName, request.UserName)
	}
	if decoded.DestIP != request.DestIP {
		t.Fatalf("decoded destIP = %q, want %q", decoded.DestIP, request.DestIP)
	}
	signature := decoded.XRequestSig
	decoded.XRequestSig = ""
	unsigned, err := json.Marshal(decoded)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if want := calcXRequestSig(signKey, unsigned); signature != want {
		t.Fatalf("signature = %q, want %q", signature, want)
	}
}

func TestTCPTunnelAuthDestinationsMatchResourceType(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(10, 75, 11, 237), Port: 443}
	for _, test := range []struct {
		name         string
		domain       string
		wantDestAddr string
		wantDestIP   string
	}{
		{name: "IP resource", wantDestAddr: "10.75.11.237:443"},
		{name: "domain resource", domain: "service.internal", wantDestAddr: "service.internal:443", wantDestIP: "10.75.11.237"},
	} {
		t.Run(test.name, func(t *testing.T) {
			destAddr, destIP := tcpTunnelAuthDestinations(addr, test.domain)
			if destAddr != test.wantDestAddr || destIP != test.wantDestIP {
				t.Fatalf("destinations = (%q, %q), want (%q, %q)", destAddr, destIP, test.wantDestAddr, test.wantDestIP)
			}
		})
	}
}

func TestTCPTunnelAuthRequestOmitsEmptyDestIP(t *testing.T) {
	data, err := json.Marshal(tcpTunnelAuthRequest{DestAddr: "10.75.11.237:443"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["destIP"]; ok {
		t.Fatalf("empty destIP was serialized: %s", data)
	}
}

func TestEncodeTCPTunnelAuthLengthRejectsOverflow(t *testing.T) {
	encoded, err := encodeTCPTunnelAuthLength(0xFFFF)
	if err != nil {
		t.Fatalf("encodeTCPTunnelAuthLength() error = %v", err)
	}
	if got := binary.BigEndian.Uint16(encoded[:]); got != 0xFFFF {
		t.Fatalf("encoded length = %d, want %d", got, 0xFFFF)
	}
	if _, err := encodeTCPTunnelAuthLength(0x10000); err == nil {
		t.Fatal("encodeTCPTunnelAuthLength() accepted an overflowing length")
	}
}

type shortWriter struct{}

func (shortWriter) Write(data []byte) (int, error) {
	return len(data) - 1, nil
}

func TestWriteTCPTunnelHandshakeMessageRejectsShortWrite(t *testing.T) {
	err := writeTCPTunnelHandshakeMessage(shortWriter{}, []byte{1, 2, 3})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("writeTCPTunnelHandshakeMessage() error = %v, want io.ErrShortWrite", err)
	}
}

func TestWriteTCPTunnelInitialMessagesSelectsWireHandshake(t *testing.T) {
	initMsg := []byte("init")
	destMsg := []byte("dest")
	var got bytes.Buffer
	if err := writeTCPTunnelInitialMessages(&got, initMsg, destMsg); err != nil {
		t.Fatal(err)
	}
	if got.String() != "initdest" {
		t.Fatalf("wire handshake = %q, want initdest", got.String())
	}
}

func TestEncodeTCPTunnelDestinationCopiesZeroRTTToRSV(t *testing.T) {
	for _, test := range []struct {
		name    string
		zeroRTT bool
		rsv     byte
	}{
		{name: "disabled", zeroRTT: false, rsv: 0},
		{name: "enabled", zeroRTT: true, rsv: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := []byte{0x05, 0x01, test.rsv, 0x01, 10, 75, 11, 237, 0x00, 0x50}
			got, err := encodeTCPTunnelDestination(net.IPv4(10, 75, 11, 237), "", 80, test.zeroRTT)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("destination = % x, want % x", got, want)
			}
		})
	}
}

func TestEncodeTCPTunnelDestinationUsesDomainAddress(t *testing.T) {
	domain := "service.internal"
	want := append([]byte{0x05, 0x01, 0x01, 0x03, byte(len(domain))}, domain...)
	want = append(want, 0x01, 0xBB)

	got, err := encodeTCPTunnelDestination(nil, domain, 443, true)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("domain destination = % x, want % x", got, want)
	}
}

func TestEncodeTCPTunnelDestinationRejectsOversizedDomain(t *testing.T) {
	domain := strings.Repeat("a", 0x100)
	if _, err := encodeTCPTunnelDestination(nil, domain, 443, false); err == nil || !strings.Contains(err.Error(), "domain too long") {
		t.Fatalf("encodeTCPTunnelDestination() error = %v, want domain length error", err)
	}
}

func TestWaitForTCPAuthPreservesBufferedRawData(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("HTTP/1.1 200 OK\r\n")
	serverErrCh := make(chan error, 1)
	go func() {
		responseJSON := []byte(`{"code":0,"message":"Successful"}`)
		response := []byte{0x53, 0x00, 0x00, byte(len(responseJSON))}
		response = append(response, responseJSON...)
		response = append(response, payload...)
		_, err := server.Write(response)
		serverErrCh <- err
	}()

	reader := bufio.NewReader(client)
	if err := waitForTCPAuth(context.Background(), client, reader); err != nil {
		t.Fatal(err)
	}
	conn := &tcpTunnelConn{tlsConn: client, reader: reader, raw: true}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("raw payload = %q, want %q", got, payload)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatal(err)
	}
}

func TestWaitForTCPAuthHandlesSplitResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		responseJSON := []byte(`{"code":0,"message":"Successful"}`)
		response := append([]byte{0x53, 0x00, 0x00, byte(len(responseJSON))}, responseJSON...)
		for _, b := range response {
			if _, err := server.Write([]byte{b}); err != nil {
				serverErrCh <- err
				return
			}
		}
		serverErrCh <- nil
	}()
	if err := waitForTCPAuth(context.Background(), client, bufio.NewReader(client)); err != nil {
		t.Fatal(err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatal(err)
	}
}

func TestCapturedRawHandshakeConsumesConnectReplyBeforeHTTP(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	payload := []byte("HTTP/1.1 200 OK\r\n")
	serverErrCh := make(chan error, 1)
	go func() {
		responseJSON := []byte(`{"code":0,"message":"Successful"}`)
		response := []byte{0x05, 0x81, 0x53, 0x00, 0x00, byte(len(responseJSON))}
		response = append(response, responseJSON...)
		response = append(response, []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}...)
		response = append(response, payload...)
		_, err := server.Write(response)
		serverErrCh <- err
	}()

	reader := bufio.NewReader(client)
	reuse, err := waitForTCPConnectReply(context.Background(), client, reader)
	if err != nil {
		t.Fatal(err)
	}
	if reuse {
		t.Fatal("captured SOCKS5 reply unexpectedly enabled reuse")
	}
	tunnelConn := &tcpTunnelConn{tlsConn: client, reader: reader, raw: true}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(tunnelConn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("raw payload = %q, want %q", got, payload)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatal(err)
	}
}

func TestResolveServerVersionInfoUsesValidatedSource(t *testing.T) {
	cached := []byte("cached")
	fetched := []byte("fetched")
	if got, err := resolveServerVersionInfo(cached, fetched, nil); err != nil || !bytes.Equal(got, fetched) {
		t.Fatalf("successful refresh = %q, %v; want fetched", got, err)
	}
	if got, err := resolveServerVersionInfo(cached, nil, errors.New("offline")); err != nil || !bytes.Equal(got, cached) {
		t.Fatalf("failed refresh = %q, %v; want cached", got, err)
	}
	if _, err := resolveServerVersionInfo(nil, nil, errors.New("offline")); err == nil || !strings.Contains(err.Error(), "failed to acquire") {
		t.Fatalf("missing manifest error = %v", err)
	}
}

func TestTCPTunnelRawDataPath(t *testing.T) {
	underlying := &recordingConn{}
	conn := &tcpTunnelConn{
		tlsConn: underlying,
		reader:  bufio.NewReader(bytes.NewReader([]byte("response"))),
		raw:     true,
	}

	buf := make([]byte, 3)
	var got []byte
	for {
		n, err := conn.Read(buf)
		got = append(got, buf[:n]...)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if string(got) != "response" {
		t.Fatalf("raw read = %q, want response", got)
	}
	if n, err := conn.Write([]byte("request")); err != nil || n != len("request") {
		t.Fatalf("raw Write() = %d, %v", n, err)
	}
	if underlying.String() != "request" {
		t.Fatalf("raw wire write = %q, want request", underlying.String())
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if !underlying.writeClosed {
		t.Fatal("raw CloseWrite() did not half-close the transport")
	}
}

func runTCPConnectExchange(t *testing.T, status byte) error {
	t.Helper()

	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})

	serverErrCh := make(chan error, 1)
	go func() {
		setupResponse := append([]byte{0x05, 0x81, 0x53, 0x00, 0x00, 0x21}, []byte(`{"code":0,"message":"Successful"}`)...)
		for _, value := range setupResponse {
			if _, err := server.Write([]byte{value}); err != nil {
				serverErrCh <- err
				return
			}
		}

		reply := []byte{0x05, status, 0x00, 0x01}
		if status == 0x00 {
			reply = append(reply, 10, 0, 0, 1, 0x1F, 0x90)
		}
		_, err := server.Write(reply)
		serverErrCh <- err
	}()

	err := waitForTCPConnect(context.Background(), client, bufio.NewReader(client))
	if serverErr := <-serverErrCh; serverErr != nil {
		t.Fatalf("server exchange failed: %v", serverErr)
	}
	return err
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
			err := runTCPConnectExchange(t, test.status)
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

func TestMatchTCPIPResourceUsesLastMatchingRule(t *testing.T) {
	resources := []client.IPResource{
		{IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 10), PortMin: 443, PortMax: 443, Protocol: "tcp", AppID: "first"},
		{IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 10), PortMin: 1, PortMax: 65535, Protocol: "all", AppID: "last"},
	}
	resource, ok := matchTCPIPResource(ipresource.New(resources), &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 443})
	if !ok {
		t.Fatal("matchTCPIPResource() did not find matching resource")
	}
	if resource.AppID != "last" {
		t.Fatalf("matched AppID = %q, want last matching rule", resource.AppID)
	}
}

func TestMatchTCPIPResourceRejectsTCPPrefL3(t *testing.T) {
	resources := []client.IPResource{{
		IPMin: net.IPv4(10, 0, 0, 1), IPMax: net.IPv4(10, 0, 0, 10), PortMin: 443, PortMax: 443,
		Protocol: "tcp", AppID: "l3-app", EnableTCPPrefL3: true,
	}}
	if resource, ok := matchTCPIPResource(ipresource.New(resources), &net.TCPAddr{IP: net.IPv4(10, 0, 0, 5), Port: 443}); ok {
		t.Fatalf("matchTCPIPResource() = %#v, want no TCP tunnel resource", resource)
	}
}

func TestDialTCPRejectsDestinationWithoutTCPResource(t *testing.T) {
	atrustClient := &Client{resourceIndex: ipresource.New(nil)}
	_, err := atrustClient.DialTCP(context.Background(), &net.TCPAddr{
		IP:   net.IPv4(223, 5, 5, 5),
		Port: 53,
	})
	if !errors.Is(err, client.ErrResourceNotFound) {
		t.Fatalf("DialTCP() error = %v, want client.ErrResourceNotFound", err)
	}
}
