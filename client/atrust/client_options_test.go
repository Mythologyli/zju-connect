package atrust

import (
	"bytes"
	stdlog "log"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/log"
	"github.com/mythologyli/zju-connect/underlay"
)

// TestSessionDebugMaterialRedactsTheSignKey: the debug dump names the session
// material, and the sign key is a credential. It may appear only in Redact form.
func TestSessionDebugMaterialRedactsTheSignKey(t *testing.T) {
	const signKey = "0123456789abcdef0123456789abcdef"
	c := NewClient(ClientOptions{Session: SessionOptions{
		SID: "sid", DeviceID: "device", SignKey: signKey,
	}})
	t.Cleanup(c.Close)
	c.ConnectionID = "connection"

	oldOutput := stdlog.Writer()
	var output bytes.Buffer
	stdlog.SetOutput(&output)
	t.Cleanup(func() { stdlog.SetOutput(oldOutput) })
	log.EnableDebug()
	t.Cleanup(log.DisableDebug)

	c.debugSessionMaterial()

	got := output.String()
	if strings.Contains(got, signKey) {
		t.Fatalf("debug output contains the sign key: %q", got)
	}
	if !strings.Contains(got, log.Redact(signKey)) {
		t.Fatalf("debug output does not carry the redacted key: %q", got)
	}
}

func TestNewClientMapsOptions(t *testing.T) {
	dialer, err := underlay.New(underlay.Options{AutoDetect: false})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = dialer.Close() })
	var keyLogWriter strings.Builder

	c := NewClient(ClientOptions{
		Session: SessionOptions{
			Username: "user",
			SID:      "sid",
			DeviceID: "device-id",
			SignKey:  "sign-key",
		},
		UnderlayDialer:  dialer,
		TLSKeyLogWriter: &keyLogWriter,
	})
	t.Cleanup(c.Close)

	if c.Username != "user" || c.SID != "sid" || c.DeviceID != "device-id" || c.SignKey != "sign-key" {
		t.Fatalf("session options were not mapped: %+v", c)
	}
	if c.underlayDialer != dialer || c.tlsKeyLogWriter != &keyLogWriter {
		t.Fatal("transport dependencies were not mapped")
	}
}

func TestCanResumeTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name         string
		sid          string
		deviceID     string
		resourceData []byte
		want         bool
	}{
		{name: "all present", sid: "sid", deviceID: "device", resourceData: []byte("resource"), want: true},
		{name: "empty but present resource", sid: "sid", deviceID: "device", resourceData: []byte{}, want: true},
		{name: "missing SID", deviceID: "device", resourceData: []byte("resource")},
		{name: "missing device", sid: "sid", resourceData: []byte("resource")},
		{name: "nil resource", sid: "sid", deviceID: "device"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(ClientOptions{Session: SessionOptions{SID: tt.sid, DeviceID: tt.deviceID}})
			t.Cleanup(c.Close)
			if got := c.canResume(tt.resourceData); got != tt.want {
				t.Fatalf("canResume() = %t, want %t", got, tt.want)
			}
		})
	}
}
