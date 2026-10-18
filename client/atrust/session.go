package atrust

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	if csrfToken != "" {
		c.clientAuthData.CSRFToken = csrfToken
	}
	c.sessionMu.Unlock()

	c.persistAuthData()
}

// persistAuthData writes the session material and returns what it wrote. It is the
// only writer of the client data file, so the renewal, the restore and the ladder
// cannot disagree about what the file holds. A renewal that produced the same
// snapshot leaves the file alone: the material did not change.
func (c *Client) persistAuthData() []byte {
	c.sessionMu.Lock()
	save := c.saveClientData
	data := c.clientAuthData
	if c.SIDTicket != "" {
		// The client's own field is the source of truth: it is where a ticket minted
		// at setup or by the ladder lands. Writing anything else here loses it on
		// restart, and the ladder then has nothing to restore from.
		data.SIDTicket = c.SIDTicket
	}
	c.sessionMu.Unlock()

	encoded, err := json.Marshal(data)
	if err != nil {
		log.Printf("Failed to marshal client data: %v", err)
		return nil
	}

	c.sessionMu.Lock()
	if bytes.Equal(encoded, c.lastPersisted) {
		c.sessionMu.Unlock()
		return encoded
	}
	c.lastPersisted = append([]byte(nil), encoded...)
	c.sessionMu.Unlock()

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

			c.sessionMu.RLock()
			recovering := c.recovering
			state := c.sessionState
			c.sessionMu.RUnlock()

			if recovering || state == SessionReloginRequired {
				// A ladder run is in flight, or the session is waiting for a new
				// login: do not pile portal requests onto it. Note that `restoring`
				// is *not* in this list - a restore waits for tunnel traffic to
				// confirm it, and if nothing confirms it the renewal is the only
				// thing that would notice the session dying again.
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
				// whole process (and the TUN device and routes) down with it. The
				// ladder publishes the state; a separate momentary "renewing"
				// state had no consumer.
				c.reportSessionInvalid(sessionCodeFromError(err), "session refresh")
				timer.Reset(interval)
			default:
				log.Printf("aTrust authConfig refresh failed: %v", err)
				timer.Reset(min(interval, time.Minute))
			}
		}
	}()
}

// sessionCodeFromError returns the portal code the auth layer carried on the
// error, so the state line and the ladder report the gateway's code instead of a
// bare string. Classification happens where the answer is parsed, not here.
func sessionCodeFromError(err error) int64 {
	code, ok := auth.CodeFromError(err)
	if !ok {
		return 0
	}
	return int64(code)
}
