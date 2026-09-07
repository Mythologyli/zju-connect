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

func TestSessionRefreshPublishesAndPersistsThenStopsOnInvalid(t *testing.T) {
	c := NewClient(ClientOptions{Session: SessionOptions{SID: "old"}})
	defer c.Close()
	persisted := make(chan []byte, 1)
	calls := 0
	c.startSessionRefresh(func(ctx context.Context) (auth.LoginResult, error) {
		calls++
		if calls == 1 {
			return auth.LoginResult{SID: "new", Cookies: []auth.Cookie{{Name: "sid", Value: "new"}}}, nil
		}
		return auth.LoginResult{}, auth.ErrSessionInvalid
	}, auth.ClientAuthData{DeviceID: "device", ServerVersionInfo: json.RawMessage(`{"code":0}`)}, func(data []byte) error {
		if sid, err := c.sessionSID(); sid != "new" || err != nil {
			t.Errorf("published SID = %q, %v", sid, err)
		}
		persisted <- data
		return nil
	}, time.Millisecond)
	select {
	case <-c.refreshDone:
	case <-time.After(time.Second):
		t.Fatal("invalid session did not stop refresh")
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
	if _, err := c.DialTCP(context.Background(), &net.TCPAddr{}); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("TCP error = %v", err)
	}
	if _, err := (clientInfo{sidProvider: c.sessionSID}).currentSID(); !errors.Is(err, auth.ErrSessionInvalid) {
		t.Fatalf("L3 error = %v", err)
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
	}, auth.ClientAuthData{}, nil, time.Millisecond)
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
