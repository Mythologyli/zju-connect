package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
)

func TestSessionRefreshPublishesAndPersists(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	persisted := make(chan []byte, 1)
	retried := make(chan struct{})
	calls := 0
	c.sessionMu.Lock()
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device", ServerVersionInfo: json.RawMessage(`{"code":0}`)}
	c.saveClientData = func(data []byte) error {
		if sid, err := c.sessionSID(); sid != "new" || err != nil {
			t.Errorf("published SID = %q, %v", sid, err)
		}
		persisted <- data
		return nil
	}
	c.sessionMu.Unlock()

	c.startSessionRefresh(func(ctx context.Context) (auth.LoginResult, error) {
		calls++
		if calls == 1 {
			return auth.LoginResult{SID: "new", Cookies: []auth.Cookie{{Name: "sid", Value: "new"}}, Ticket: "ticket-new"}, nil
		}
		close(retried)
		<-ctx.Done()
		return auth.LoginResult{}, ctx.Err()
	}, time.Millisecond)
	select {
	case <-retried:
	case <-c.refreshDone:
		t.Fatal("refresh stopped unexpectedly")
	case <-time.After(time.Second):
		t.Fatal("next refresh did not start")
	}
	if calls != 2 {
		t.Fatalf("refresh calls = %d", calls)
	}
	var saved auth.ClientAuthData
	select {
	case data := <-persisted:
		if err := json.Unmarshal(data, &saved); err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("cookies not persisted")
	}
	if saved.DeviceID != "device" || len(saved.ServerVersionInfo) == 0 || saved.Cookies[0].Value != "new" {
		t.Fatalf("saved = %+v", saved)
	}
	if saved.Ticket != "ticket-new" {
		t.Fatalf("saved ticket = %q, want the renewal ticket to survive the round trip", saved.Ticket)
	}
	if sid, err := c.sessionSID(); sid != "new" || err != nil {
		t.Fatalf("retained SID = %q, %v", sid, err)
	}
	if sid, err := (clientInfo{sidProvider: c.sessionSID}).currentSID(); sid != "new" || err != nil {
		t.Fatalf("L3 SID = %q, %v", sid, err)
	}
}

func TestSessionRefreshPreservesSIDOnTransientFailureAndCancels(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	second := make(chan struct{})
	calls := 0
	c.startSessionRefresh(func(ctx context.Context) (auth.LoginResult, error) {
		calls++
		if calls == 1 {
			return auth.LoginResult{}, errors.New("temporary network error")
		}
		close(second)
		<-ctx.Done()
		return auth.LoginResult{}, ctx.Err()
	}, time.Millisecond)
	select {
	case <-second:
	case <-time.After(time.Second):
		t.Fatal("no retry")
	}
	if sid, err := c.sessionSID(); sid != "old" || err != nil {
		t.Fatalf("SID = %q, %v", sid, err)
	}
	done := make(chan struct{})
	go func() { c.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel refresh")
	}
}

// TestSessionRefreshKeepsItsCadence: the renewal runs on the configured interval,
// not on the one-minute retry path, and the first renewal waits a full interval.
func TestSessionRefreshKeepsItsCadence(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()

	const interval = 50 * time.Millisecond
	const renewals = 5

	ticks := make(chan time.Time, renewals)
	c.sessionMu.Lock()
	c.clientAuthData = auth.ClientAuthData{DeviceID: "device"}
	c.sessionMu.Unlock()
	c.startSessionRefresh(func(context.Context) (auth.LoginResult, error) {
		ticks <- time.Now()
		return auth.LoginResult{SID: "new", Cookies: []auth.Cookie{{Name: "sid", Value: "new"}}}, nil
	}, interval)

	start := time.Now()
	for i := range renewals {
		select {
		case <-ticks:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d renewals happened", i, renewals)
		}
	}
	elapsed := time.Since(start)

	if floor := 4 * interval; elapsed < floor {
		t.Fatalf("%d renewals took %v, want at least %v", renewals, elapsed, floor)
	}
	if ceiling := 7 * interval; elapsed > ceiling {
		t.Fatalf("%d renewals took %v, want at most %v", renewals, elapsed, ceiling)
	}
}

func TestExistingL3InfoUsesCurrentSIDAndSignsIt(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	info := clientInfo{sid: "old", sidProvider: c.sessionSID}
	meta := packetMeta{atype: 4, proto: 17, srcIP: net.IPv4(192, 0, 2, 1), dstIP: net.IPv4(198, 51, 100, 2), srcPort: 1234, dstPort: 53}
	for _, sid := range []string{"first", "second"} {
		c.setSessionSID(sid, nil)
		data, err := buildAuthRequest(info, []byte("key"), meta, &conntrack{appID: "app", authID: 1})
		if err != nil {
			t.Fatal(err)
		}
		var req authRequestIP
		if err := json.Unmarshal(data, &req); err != nil {
			t.Fatal(err)
		}
		if req.Sid != sid {
			t.Fatalf("wire SID = %q, want %q", req.Sid, sid)
		}
		signature := req.XRequestSig
		req.XRequestSig = ""
		unsigned, _ := json.Marshal(req)
		if signature != calcXRequestSig([]byte("key"), unsigned) {
			t.Fatal("signature did not cover current SID")
		}
	}
	c.setSessionSID("", auth.ErrSessionInvalid)
	if _, err := buildAuthRequest(info, []byte("key"), meta, &conntrack{}); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("auth error = %v", err)
	}
}

func TestConcurrentSessionSIDReaders(t *testing.T) {
	c := NewClient(ClientOptions{})
	defer c.Close()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 1000; j++ {
				c.sessionSID()
			}
		}()
	}
	for i := 0; i < 1000; i++ {
		c.setSessionSID("new", nil)
	}
	wg.Wait()
}

// The five fatal exits on session problems are gone; what a data path and the
// renewal loop do instead is pinned in session_recovery_test.go. The old
// subprocess test that asserted an exit code of 1 is deliberately deleted: the
// process must survive, and a test that asserts the opposite cannot be adjusted.
