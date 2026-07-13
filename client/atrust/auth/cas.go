package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mythologyli/zju-connect/log"
)

type CASLogin struct {
	Domain string
	Ticket string
}

func (m CASLogin) AuthType() string {
	return "auth/cas"
}

func (m CASLogin) LoginDomain() string {
	return m.Domain
}

func (m CASLogin) login(s *Session, authInfo AuthInfo) error {
	return s.loginAuthCas(authInfo.LoginURL, m.Domain, m.Ticket)
}

func (s *Session) loginAuthCas(loginURL, loginDomain, ticket string) error {
	callback := s.casCallbackFromTicket(loginDomain, ticket)
	if ticket == "" {
		var err error
		callback, err = s.interactiveCas(loginURL)
		if err != nil {
			return err
		}
	}

	if err := s.cas(callback); err != nil {
		return err
	}
	_, _, err := s.authConfig(true, false)
	return err
}

func (s *Session) casCallbackFromTicket(loginDomain, ticket string) string {
	params := url.Values{
		"sfDomain": {loginDomain},
		"ticket":   {ticket},
	}
	return s.baseURL + "/passport/v1/auth/cas?" + params.Encode()
}

func (s *Session) interactiveCas(loginURL string) (string, error) {
	log.Printf("Visit %s to login, and catch the callback url", loginURL)
	log.Println("Please enter the callback url:")
	var callback string
	_, err := fmt.Scanln(&callback)
	if err != nil {
		return "", err
	}

	callbackURL, err := url.Parse(callback)
	if err != nil {
		return "", err
	}
	if err := validateCASCallbackURL(callbackURL, s.baseHost); err != nil {
		return "", err
	}
	return callback, nil
}

func validateCASCallbackURL(callbackURL *url.URL, baseHost string) error {
	if callbackURL.Scheme != "https" {
		return fmt.Errorf("invalid callback url: scheme not https")
	}
	if callbackURL.Host != baseHost {
		return fmt.Errorf("invalid callback url: host not match")
	}
	if callbackURL.Path != "/passport/v1/auth/cas" {
		return fmt.Errorf("invalid callback url: path not match")
	}
	queries := callbackURL.Query()
	if queries.Get("ticket") == "" {
		return fmt.Errorf("invalid callback url: ticket not found")
	}
	return nil
}

func (s *Session) cas(callback string) error {
	log.Println("Perform GET /passport/v1/auth/cas")

	req, _ := http.NewRequest("GET", callback, nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	prevCheckRedirect := s.client.CheckRedirect
	s.client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer func() { s.client.CheckRedirect = prevCheckRedirect }()

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	if resp.StatusCode != 302 {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}
	ticket, err := parsePortalTicketFromRedirect(resp.Header.Get("Location"), s.baseHost)
	if err != nil {
		return err
	}

	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received cas data: %s", string(body))
	s.ticket = ticket
	return nil
}
