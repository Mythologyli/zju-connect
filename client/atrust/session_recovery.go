package atrust

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/client/atrust/auth"
	"github.com/mythologyli/zju-connect/log"
)

// SessionState is what the session maintenance last learned about the session. It
// is the state the caller (and the GUI) acts on, and every change is on stdout in
// a stable format so it can be followed without reading the prose log.
type SessionState string

const (
	SessionOnline          SessionState = "online"
	SessionRestoring       SessionState = "restoring"
	SessionReloginRequired SessionState = "relogin-required"
)

const (
	// sessionRecoveryCooldown keeps a session that keeps dying from hammering the
	// portal: at most one ladder run per window, however many detectors fire. It
	// is also the only retry clock for an automatic re-login.
	sessionRecoveryCooldown = time.Minute
)

// sessionInvalidError is what a data-plane answer that says the session is gone
// becomes: the caller's request fails and the client learns about it, but nothing
// exits and the listeners stay up.
type sessionInvalidError struct {
	Where   string
	Code    int64
	Message string
}

func (e *sessionInvalidError) Error() string {
	return fmt.Sprintf("%s: aTrust session is invalid (code %d): %s", e.Where, e.Code, e.Message)
}

func (e *sessionInvalidError) Unwrap() error { return auth.ErrSessionInvalid }

// isSessionInvalidCode reports whether a data-plane code means the session is
// gone; 75500001 is the timeout variant of 75500002.
func isSessionInvalidCode(code int64) bool {
	return auth.IsSessionDeathCode(int(code))
}

func (c *Client) currentSessionState() SessionState {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.sessionState
}

// setSessionState publishes a state change once: the stable stdout line is the
// contract a caller follows without parsing prose, and the reauthentication line
// is the one a UI is expected to grep.
func (c *Client) setSessionState(state SessionState, reason string, code int64) {
	c.sessionMu.Lock()
	if c.sessionState == state {
		c.sessionMu.Unlock()
		return
	}
	c.sessionState = state
	c.sessionMu.Unlock()

	log.Printf("aTrust session state: %s reason=%s code=%d", state, reason, code)
	if state == SessionReloginRequired {
		log.Printf("aTrust session requires reauthentication (code=%d)", code)
	}
}

// ObserveTunnelTraffic reports that application traffic crossed the tunnel. After
// a restore this is the proof that the session works; a VIP being allocated is
// not (a resumed tunnel with a mismatched sign key carried nothing).
func (c *Client) ObserveTunnelTraffic(ok bool) {
	if !ok || c.currentSessionState() != SessionRestoring {
		return
	}
	c.setSessionState(SessionOnline, "tunnel traffic confirmed", 0)
}

// reportSessionInvalid is what every data path calls when the gateway says the
// session is gone: it publishes the state and runs the ladder once, while the
// caller keeps its own error. Once the ladder has reached relogin-required, a
// data-plane kick is not a new fact: with auto re-login off it is dropped, and
// with it on the cooldown is the only retry clock, so a request storm cannot
// become a login storm.
func (c *Client) reportSessionInvalid(code int64, where string) {
	c.sessionMu.RLock()
	state := c.sessionState
	blocked := state == SessionReloginRequired && (!c.autoRelogin || c.reloginBlocked)
	c.sessionMu.RUnlock()
	if state == "" {
		// Setup has not finished: there is nothing to recover yet, and the setup
		// call's own error is what the caller sees.
		log.Printf("aTrust session invalid during setup (%s, code %d)", where, code)
		return
	}
	if blocked {
		return
	}
	go c.runSessionRecovery(code, where)
}

// reportIfSessionInvalid routes an error that says the session is gone to the
// ladder; anything else is the caller's to handle.
func (c *Client) reportIfSessionInvalid(err error, where string) {
	var invalid *sessionInvalidError
	if errors.As(err, &invalid) {
		c.reportSessionInvalid(invalid.Code, where)
	}
}

// runSessionRecovery is the ladder: renew, restore from the ticket, and only then
// report that a new login is needed. Auto re-login is off by default because a
// full login rotates the device token and drops other clients of the account.
func (c *Client) runSessionRecovery(code int64, where string) {
	c.sessionMu.Lock()
	terminal := c.sessionState == SessionReloginRequired
	if c.recovering || time.Since(c.lastRecovery) < sessionRecoveryCooldown ||
		(terminal && (!c.autoRelogin || c.reloginBlocked)) {
		c.sessionMu.Unlock()
		return
	}
	c.recovering = true
	c.lastRecovery = time.Now()
	session := c.session
	c.sessionMu.Unlock()

	defer func() {
		c.sessionMu.Lock()
		c.recovering = false
		c.sessionMu.Unlock()
	}()

	if session == nil {
		// Setup owns the session until it hands the client over; a detector that
		// fires before that has no ladder to run.
		return
	}

	ctx := c.lifecycleCtx
	c.setSessionState(SessionRestoring, where, code)

	// 1. Renew: the answer may have been about a session that is merely stale.
	if snapshot, err := session.Refresh(ctx); err == nil {
		c.applySessionSnapshot(snapshot)
		c.setSessionState(SessionOnline, "renewal succeeded", 0)
		return
	} else if !errors.Is(err, auth.ErrSessionInvalid) {
		log.Printf("aTrust session recovery: renewal failed: %v", err)
	}

	// 2. Restore from the ticket.
	restored, err := c.restoreFromTicket(ctx, session)
	switch {
	case err != nil:
		log.Printf("aTrust session recovery: restore failed: %v", err)
	case restored:
		// Not Online yet: the data plane has to prove it, see ObserveTunnelTraffic.
		log.Printf("aTrust session restored; waiting for tunnel traffic to confirm it")
		return
	}

	// 3. A full login, only when the operator asked for it. One attempt per
	// cooldown: the cooldown is the retry clock, so a detector cannot turn into
	// three login POSTs in a minute.
	if c.autoRelogin {
		if err := c.relogin(ctx); err != nil {
			log.Printf("aTrust automatic re-login failed: %v", err)
			if !retryableReloginError(err) {
				// Wrong credentials or a server-side "not now": retrying every
				// cooldown cannot fix it and risks a lockout.
				c.sessionMu.Lock()
				c.reloginBlocked = true
				c.sessionMu.Unlock()
			}
		} else {
			log.Printf("aTrust automatic re-login succeeded; waiting for tunnel traffic to confirm it")
			return
		}
	}

	c.setSessionState(SessionReloginRequired, where, code)
}

// prepareRestoreTicket mints a sidTicket while the session is still alive and
// stores it. Without one, the ladder's restore step has nothing to exchange when
// the session dies: ticketExchange itself needs a live session, so the ticket has
// to be taken while the portal still answers. Best effort by design - a failure
// here costs nothing but an unattended restore.
func (c *Client) prepareRestoreTicket(ctx context.Context, session *auth.Session) {
	if c.sidTicket() != "" {
		return
	}

	ticket, err := session.TicketExchange(ctx)
	if err != nil {
		log.Printf("aTrust could not obtain a sidTicket for later restores: %v", err)
		return
	}

	c.sessionMu.Lock()
	c.SIDTicket = ticket
	c.sessionMu.Unlock()
	c.persistAuthData()
	log.Printf("aTrust sidTicket stored (%d characters); a dead session can be restored without a login", len(ticket))
}

// restoreFromTicket runs the restore step of the ladder. It returns false and no
// error when there is no ticket to try at all.
func (c *Client) restoreFromTicket(ctx context.Context, session *auth.Session) (bool, error) {
	ticket := c.sidTicket()
	if ticket == "" {
		minted, err := c.mintTicket(ctx, session)
		if err != nil {
			return false, err
		}
		ticket = minted
	}

	snapshot, err := session.RestoreByTicket(ctx, ticket)
	if errors.Is(err, auth.ErrStaleTicket) {
		// The stored ticket is no good any more: ask for a fresh one, once. That
		// needs a live session, which is exactly what is missing when the portal
		// has already expired the session - so the failure has to say both things.
		log.Printf("aTrust session recovery: the stored sidTicket was refused (%v); asking for a new one", err)
		fresh, mintErr := c.mintTicket(ctx, session)
		if mintErr != nil {
			return false, fmt.Errorf("the stored sidTicket was refused (%v) and the portal cannot issue a new one while the session is gone (%v)", err, mintErr)
		}
		snapshot, err = session.RestoreByTicket(ctx, fresh)
	}
	if err != nil {
		return false, err
	}

	c.applySessionSnapshot(snapshot)
	return true, nil
}

func (c *Client) sidTicket() string {
	c.sessionMu.RLock()
	defer c.sessionMu.RUnlock()
	return c.SIDTicket
}

// mintTicket asks the portal for a sidTicket and stores it, so a restart does not
// need a password.
func (c *Client) mintTicket(ctx context.Context, session *auth.Session) (string, error) {
	ticket, err := session.TicketExchange(ctx)
	if err != nil {
		return "", err
	}

	c.sessionMu.Lock()
	c.SIDTicket = ticket
	c.sessionMu.Unlock()
	log.Printf("aTrust sidTicket renewed (%d characters)", len(ticket))
	c.persistAuthData()
	return ticket, nil
}

// relogin repeats the login with the credentials setup was given. It makes one
// attempt: the ladder's cooldown is the retry clock, and stacking immediate
// retries on top of it is what turns a dead session into a burst of login POSTs.
func (c *Client) relogin(ctx context.Context) error {
	c.sessionMu.RLock()
	session := c.session
	method := c.loginMethod
	options := c.loginOptions
	c.sessionMu.RUnlock()

	if session == nil || method == nil {
		return errors.New("no configured login method")
	}

	options.Cookies = nil // the session's own jar carries the cookie family
	_, err := session.Login(method, options)
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

// retryableReloginError reports whether a failed login is worth another attempt.
// "Still online" and "stale random check code" are the server saying not now;
// hammering it makes that worse, and neither is a wrong credential.
func retryableReloginError(err error) bool {
	if errors.Is(err, auth.ErrSessionInvalid) || errors.Is(err, auth.ErrStaleTicket) {
		return false
	}
	if code, ok := auth.CodeFromError(err); ok {
		switch code {
		case 75500006, 75500304, 75500307:
			return false
		}
	}
	return !strings.Contains(err.Error(), "already-logged-in")
}
