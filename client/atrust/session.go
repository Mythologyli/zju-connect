package atrust

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/log"
)

func (c *Client) sessionSID() (string, error) {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.SID, c.sessionErr
}

func (c *Client) setSessionSID(sid string, err error) {
	c.sessionMu.Lock()
	c.SID, c.sessionErr = sid, err
	c.sessionMu.Unlock()
}

// applySessionSnapshot publishes the snapshot a portal answer produced (a renewal,
// a restore or a re-login): the SID the data paths sign with, and the material a
// restart needs to resume without a password.
func (c *Client) applySessionSnapshot(snapshot auth.LoginResult) {
	c.setSessionSID(snapshot.SID, nil)

	c.sessionMu.RLock()
	session := c.session
	c.sessionMu.RUnlock()

	csrfToken := ""
	if session != nil {
		csrfToken = session.CSRFToken()
	}

	c.sessionMu.Lock()
	c.clientAuthData.Cookies = snapshot.Cookies
	if c.DeviceID != "" {
		c.clientAuthData.DeviceID = c.DeviceID
	}
	if snapshot.Ticket != "" {
		c.clientAuthData.Ticket = snapshot.Ticket
	}
	if csrfToken != "" {
		c.clientAuthData.CSRFToken = csrfToken
	}
	c.sessionMu.Unlock()

	c.persistAuthData()
}

// persistAuthData writes the session material and returns what it wrote. It is the
// only writer of the client data file, so the renewal, the restore and the ladder
// cannot disagree about what the file holds.
func (c *Client) persistAuthData() []byte {
	c.sessionMu.Lock()
	save := c.saveClientData
	data := c.clientAuthData
	c.sessionMu.Unlock()

	encoded, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal client data: %v", err)
		return nil
	}
	if save != nil {
		if err := save(encoded); err != nil {
			log.Printf("Failed to save client data: %v", err)
		}
	}
	return encoded
}

// startSessionRefresh runs the renewal loop. The renewal is a validity check, not
// a keep-alive: only application traffic through the tunnel holds the session
// open, so this loop exists to notice death early and to keep the material the
// restore path needs.
func (c *Client) startSessionRefresh(refresh func(context.Context) (auth.LoginResult, error), interval time.Duration) {
	c.refreshDone = make(chan struct{})
	go func() {
		defer close(c.refreshDone)
		timer := time.NewTimer(interval)
		defer timer.Stop()
		for {
			select {
			case <-c.lifecycleCtx.Done():
				return
			case <-timer.C:
			}

			if state := c.currentSessionState(); state == SessionRestoring || state == SessionReloginRequired || state == SessionOffline {
				// A recovery is running, or the session is waiting for a new login:
				// do not pile portal requests onto it.
				timer.Reset(interval)
				continue
			}

			oldSID, _ := c.sessionSID()
			snapshot, err := refresh(c.lifecycleCtx)
			if c.lifecycleCtx.Err() != nil {
				return
			}
			switch {
			case err == nil:
				c.applySessionSnapshot(snapshot)
				log.Printf("aTrust session refreshed (SID changed: %t)", oldSID != snapshot.SID)
				timer.Reset(interval)
			case errors.Is(err, auth.ErrSessionInvalid):
				// The session is gone. This used to be log.Fatalf, which took the
				// whole process (and the TUN device and routes) down with it.
				c.setSessionState(SessionRenewing, "session refresh was refused", sessionCodeFromError(err))
				c.reportSessionInvalid(sessionCodeFromError(err), "session refresh")
				timer.Reset(interval)
			default:
				log.Printf("aTrust authConfig refresh failed: %v", err)
				timer.Reset(min(interval, time.Minute))
			}
		}
	}()
}

// sessionCodeFromError pulls the portal code out of an error message, so the state
// line and the ladder carry the code the gateway sent instead of a bare string.
func sessionCodeFromError(err error) int64 {
	if err == nil {
		return 0
	}
	message := err.Error()
	for _, code := range []int64{75500002, 75500001, 75500006, 75500304, 75500307, 10000004, 10000030, 10000000} {
		if strings.Contains(message, strconv.FormatInt(code, 10)) {
			return code
		}
	}
	return 0
}
