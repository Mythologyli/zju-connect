package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/mythologyli/zju-connect/log"
)

var (
	// ErrStaleTicket means the portal refused the sidTicket itself, so the caller
	// has to mint a new one instead of retrying the exchange.
	ErrStaleTicket = errors.New("aTrust sidTicket was refused; a new one is needed")
	// ErrRestoreNotConfirmed is the silent no-op the restore path has to guard
	// against: the gateway answers code 0 成功 and sets no cookies at all when the
	// cookie jar is empty, leaving the session dead.
	ErrRestoreNotConfirmed = errors.New("aTrust restore was not confirmed as online")
)

// TicketExchange asks the portal for a sidTicket. It needs a live session: the
// cookies carry the whole request (empty body, no CSRF token), and an expired jar
// answers a non-zero code or no data - so this is not a way around a fresh login.
func (s *Session) TicketExchange(ctx context.Context) (string, error) {
	log.Println("Perform POST /passport/v1/public/ticketExchange")

	u := s.baseURL + "/passport/v1/public/ticketExchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u+"?"+WithSharedParams(nil).Encode(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", UserAgent)
	// Measured against the gateway: this POST only succeeds with a JSON content
	// type. Without it the portal answers 401 with an empty body - even though the
	// request carries no body at all - which then looks like a JSON parse failure.
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-csrf-token", s.CSRFToken())
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	log.DebugPrintf("Received ticket exchange: %s", log.RedactSecrets(string(body)))

	if resp.StatusCode != http.StatusOK {
		// A refusal with no body must not be reported as a parse failure.
		return "", fmt.Errorf("ticketExchange HTTP %d", resp.StatusCode)
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			SIDTicket string `json:"sidTicket"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return "", fmt.Errorf("ticketExchange returned invalid json: %w", err)
	}
	if re.Code != 0 {
		return "", ticketError("ticketExchange", re.Code, re.Message)
	}
	if re.Data.SIDTicket == "" {
		return "", fmt.Errorf("%w: ticketExchange answered code 0 without a sidTicket", ErrRestoreNotConfirmed)
	}
	return re.Data.SIDTicket, nil
}

// RestoreByTicket exchanges a sidTicket for a session and confirms it. The order
// is the official one: authConfig (which is what produces the cookie family the
// exchange needs), sessionIdExchange, authConfig, onlineInfo. A code 0 answer is
// never taken as success on its own.
func (s *Session) RestoreByTicket(ctx context.Context, sidTicket string) (LoginResult, error) {
	if sidTicket == "" {
		return LoginResult{}, errors.New("aTrust restore: no sidTicket")
	}

	// Pre-flight: build the cookie family the exchange runs on. A dead session
	// answers an error here, which is why the result is logged, not returned.
	if _, _, err := s.authConfigContext(ctx, false, true, false); err != nil {
		log.Printf("aTrust restore: pre-flight authConfig: %v", err)
	}

	if err := s.sessionIDExchange(ctx, sidTicket); err != nil {
		return LoginResult{}, err
	}
	if _, _, err := s.authConfigContext(ctx, false, false, true); err != nil {
		return LoginResult{}, err
	}
	info, err := s.onlineInfoContext(ctx)
	if err != nil {
		return LoginResult{}, err
	}
	if info.Online == nil || !*info.Online {
		return LoginResult{}, fmt.Errorf("%w: onlineInfo did not report an online session", ErrRestoreNotConfirmed)
	}

	return s.Snapshot()
}

func (s *Session) sessionIDExchange(ctx context.Context, sidTicket string) error {
	log.Println("Perform POST /passport/v1/public/sessionIdExchange")

	payload, err := json.Marshal(map[string]string{"sidTicket": sidTicket})
	if err != nil {
		return err
	}

	u := s.baseURL + "/passport/v1/public/sessionIdExchange"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-csrf-token", s.CSRFToken())
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.request(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.DebugPrintf("Received session id exchange: %s", log.RedactSecrets(string(body)))

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("sessionIdExchange HTTP %d", resp.StatusCode)
	}

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			IsOnline   *bool `json:"isOnline"`
			OnlineInfo *struct {
				IsOnline *bool `json:"isOnline"`
			} `json:"onlineInfo"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return fmt.Errorf("sessionIdExchange returned invalid json: %w", err)
	}
	if re.Code != 0 {
		return ticketError("sessionIdExchange", re.Code, re.Message)
	}

	// The exchange returns the online state itself, either flat or nested inside
	// onlineInfo; anything else is the silent no-op this guards against.
	var online *bool
	if re.Data.IsOnline != nil {
		online = re.Data.IsOnline
	} else if re.Data.OnlineInfo != nil {
		online = re.Data.OnlineInfo.IsOnline
	}
	if online == nil || !*online {
		return fmt.Errorf("%w: sessionIdExchange answered code 0 without an online session", ErrRestoreNotConfirmed)
	}
	return nil
}
