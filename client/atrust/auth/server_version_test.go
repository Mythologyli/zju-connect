package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServerVersionInfoSelectsTCPTunnelZeroRTT(t *testing.T) {
	for _, test := range []struct {
		name    string
		version string
		enable  bool
		want    bool
	}{
		{name: "supported and enabled", version: "1.0.0.0", enable: true, want: true},
		{name: "missing capability", enable: true},
		{name: "disabled by option", version: "1.0.0.0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			manifest := fmt.Sprintf(`{"code":0,"data":{"capacities":{"zeroRTT":{"version":%q}},"options":{"tun0rtt":{"enable":%t}}}}`, test.version, test.enable)
			info, err := ParseServerVersionInfo([]byte(manifest))
			if err != nil {
				t.Fatal(err)
			}
			if got := info.TCPTunnelZeroRTT(); got != test.want {
				t.Fatalf("TCPTunnelZeroRTT() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestServerVersionInfoFetchesAndValidatesManifest(t *testing.T) {
	manifest := `{"code":0,"data":{"capacities":{"zeroRTT":{"version":"1.0.0.0"}},"options":{"tun0rtt":{"enable":true}}}}`
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/public/manifest" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		_, _ = w.Write([]byte(manifest))
	}))
	defer server.Close()

	got, err := newTLSTestSession(server).ServerVersionInfo()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != manifest {
		t.Fatalf("ServerVersionInfo() = %q, want %q", got, manifest)
	}
}

func TestServerVersionInfoRejectsInvalidResponse(t *testing.T) {
	for _, test := range []struct {
		name       string
		status     int
		body       string
		wantErrMsg string
	}{
		{name: "HTTP failure", status: http.StatusBadGateway, body: `{}`, wantErrMsg: "HTTP status 502"},
		{name: "invalid JSON", status: http.StatusOK, body: `{`, wantErrMsg: "failed to parse"},
		{name: "manifest failure", status: http.StatusOK, body: `{"code":17}`, wantErrMsg: "code 17"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			}))
			defer server.Close()
			_, err := newTLSTestSession(server).ServerVersionInfo()
			if err == nil || !strings.Contains(err.Error(), test.wantErrMsg) {
				t.Fatalf("ServerVersionInfo() error = %v, want %q", err, test.wantErrMsg)
			}
		})
	}
}
