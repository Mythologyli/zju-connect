package atrust

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/underlay"
)

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
		signKey      string
		resourceData []byte
		want         bool
	}{
		{name: "all present", sid: "sid", deviceID: "device", signKey: "key", resourceData: []byte("resource"), want: true},
		{name: "empty but present resource", sid: "sid", deviceID: "device", signKey: "key", resourceData: []byte{}, want: true},
		{name: "missing SID", deviceID: "device", signKey: "key", resourceData: []byte("resource")},
		{name: "missing device", sid: "sid", signKey: "key", resourceData: []byte("resource")},
		{name: "nil resource", sid: "sid", deviceID: "device", signKey: "key"},
		// A stored session without the key it was minted with is not resumable:
		// minting a fresh one brings the tunnel up while every authorization
		// through it is rejected.
		{name: "missing sign key", sid: "sid", deviceID: "device", resourceData: []byte("resource")},
		// A key without the device id it was paired with is just as unusable.
		{name: "sign key without a device id", sid: "sid", signKey: "key", resourceData: []byte("resource")},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(ClientOptions{Session: SessionOptions{SID: tt.sid, DeviceID: tt.deviceID, SignKey: tt.signKey}})
			t.Cleanup(c.Close)
			if got := c.canResume(tt.resourceData); got != tt.want {
				t.Fatalf("canResume() = %t, want %t", got, tt.want)
			}
		})
	}
}

// TestCanRestoreByTicketTruthTable pins the prerequisites of a password-free
// restore: the exchange needs the ticket, and the restored session needs the same
// device/sign-key pair it was minted with. Nothing about the resource file: the
// list is fetched through the restored session.
func TestCanRestoreByTicketTruthTable(t *testing.T) {
	for _, tt := range []struct {
		name     string
		ticket   string
		deviceID string
		signKey  string
		want     bool
	}{
		{name: "all present", ticket: "ticket", deviceID: "device", signKey: "key", want: true},
		{name: "missing ticket", deviceID: "device", signKey: "key"},
		{name: "missing device", ticket: "ticket", signKey: "key"},
		{name: "missing sign key", ticket: "ticket", deviceID: "device"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			c := NewClient(ClientOptions{Session: SessionOptions{
				SIDTicket: tt.ticket, DeviceID: tt.deviceID, SignKey: tt.signKey,
			}})
			t.Cleanup(c.Close)
			if got := c.canRestoreByTicket(); got != tt.want {
				t.Fatalf("canRestoreByTicket() = %t, want %t", got, tt.want)
			}
		})
	}
}

// TestClientAuthDataKeepsTheResumeMaterial: the sign key is only useful if it
// survives the client-data round trip, together with the device id it is paired
// with and the sidTicket the restore path exchanges.
func TestClientAuthDataKeepsTheResumeMaterial(t *testing.T) {
	saved := auth.ClientAuthData{
		Cookies:   []auth.Cookie{{Host: "vpn.example", Scheme: "https", Name: "sid", Value: "sid-1"}},
		DeviceID:  "device-1",
		SignKey:   "sign-key-1",
		SIDTicket: "sid-ticket-1",
		CSRFToken: "csrf-1",
	}

	encoded, err := json.Marshal(saved)
	if err != nil {
		t.Fatal(err)
	}
	var loaded auth.ClientAuthData
	if err := json.Unmarshal(encoded, &loaded); err != nil {
		t.Fatal(err)
	}

	if loaded.SignKey != saved.SignKey || loaded.DeviceID != saved.DeviceID {
		t.Fatalf("resume pair = (%q, %q), want (%q, %q)",
			loaded.SignKey, loaded.DeviceID, saved.SignKey, saved.DeviceID)
	}
	if loaded.SIDTicket != saved.SIDTicket {
		t.Fatalf("sidTicket = %q, want %q", loaded.SIDTicket, saved.SIDTicket)
	}
	if loaded.CSRFToken != saved.CSRFToken || len(loaded.Cookies) != 1 {
		t.Fatalf("session material = %+v, want the csrf token and the cookies", loaded)
	}

	// A file written before these fields existed must still load.
	var legacy auth.ClientAuthData
	if err := json.Unmarshal([]byte(`{"cookies":[],"device_id":"device-1"}`), &legacy); err != nil {
		t.Fatalf("an older client data file no longer loads: %v", err)
	}
	if legacy.SignKey != "" || legacy.SIDTicket != "" {
		t.Fatalf("legacy record = %+v, want empty resume material", legacy)
	}
}
