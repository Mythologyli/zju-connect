package atrust

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestReadIPTunnelResponses(t *testing.T) {
	auth := []byte(`{"code":0,"message":"OK"}`)
	response := []byte{0x05, 0xD0, 0x53, 0x00, byte(len(auth) >> 8), byte(len(auth))}
	response = append(response, auth...)
	response = append(response, 0x05, 0x00, 0x7F, 0x01, 10, 249, 8, 102, 0x00, 0x00)

	ip, err := readIPTunnelResponses(bytes.NewReader(response))
	if err != nil {
		t.Fatalf("readIPTunnelResponses() error = %v", err)
	}
	if got := ip.String(); got != "10.249.8.102" {
		t.Fatalf("VIP = %s, want 10.249.8.102", got)
	}
}

func TestReadIPTunnelResponsesRejectsAuthStatusWithoutLosingFraming(t *testing.T) {
	auth := []byte(`{"code":1,"message":"denied"}`)
	response := []byte{0x05, 0xD0, 0x53, 0x81, byte(len(auth) >> 8), byte(len(auth))}
	response = append(response, auth...)
	reader := bytes.NewReader(response)

	_, err := readIPTunnelResponses(reader)
	if err == nil || !strings.Contains(err.Error(), "status 129") {
		t.Fatalf("readIPTunnelResponses() error = %v", err)
	}
	if reader.Len() != 0 {
		t.Fatalf("unread auth response bytes = %d", reader.Len())
	}
}

func TestIPVIPResponseIgnoresThirdHeaderByte(t *testing.T) {
	ip, err := parseIPv4VIPResponse([]byte{0x01, 0x01, 10, 249, 8, 102})
	if err != nil {
		t.Fatalf("parseIPv4VIPResponse() error = %v", err)
	}
	if got := ip.String(); got != "10.249.8.102" {
		t.Fatalf("VIP = %s, want 10.249.8.102", got)
	}
}

func TestIPAuthRequestUsesEncodedJSONLength(t *testing.T) {
	payload, err := json.Marshal(authRequestSID{Sid: `sid-with-"-quote`})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	request := wrapAuthReqData(payload, 1)
	if got := int(binary.BigEndian.Uint16(request[5:7])); got != len(payload) {
		t.Fatalf("auth payload length = %d, want %d", got, len(payload))
	}
	if got := request[7 : 7+len(payload)]; string(got) != string(payload) {
		t.Fatalf("auth payload = %q, want %q", got, payload)
	}
	if got := request[7+len(payload):]; string(got) != string([]byte{0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
		t.Fatalf("VIP request = % X", got)
	}
}

func TestParseIPAuthResponseUsesResponseCode(t *testing.T) {
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
			err := parseIPAuthResponse([]byte(test.response))
			if test.wantErrMsg == "" {
				if err != nil {
					t.Fatalf("parseIPAuthResponse() error = %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), test.wantErrMsg) {
				t.Fatalf("parseIPAuthResponse() error = %v, want message %q", err, test.wantErrMsg)
			}
		})
	}
}
