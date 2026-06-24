package auth

import (
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mythologyli/zju-connect/log"
)

type HTTPSOauth2Login struct {
	Domain   string
	Code     string
	Callback string
}

func (m HTTPSOauth2Login) AuthType() string {
	return "auth/httpsOauth2"
}

func (m HTTPSOauth2Login) LoginDomain() string {
	return m.Domain
}

func (m HTTPSOauth2Login) login(s *Session, authInfo AuthInfo) error {
	return s.loginAuthHttpsOauth2(authInfo.LoginURL, m.Domain, m.Code, m.Callback)
}

func (s *Session) loginAuthHttpsOauth2(loginURL, loginDomain, code, callback string) error {
	if callback == "" && code != "" {
		callback = s.httpsOauth2CallbackFromCode(loginDomain, code)
	}
	if callback == "" {
		var err error
		callback, err = s.interactiveHttpsOauth2(loginURL)
		if err != nil {
			return err
		}
	}

	if err := s.httpsOauth2(callback); err != nil {
		return err
	}

	_, _, err := s.authConfigMod()
	return err
}

func (s *Session) httpsOauth2CallbackFromCode(loginDomain, code string) string {
	params := url.Values{
		"sfDomain": {loginDomain},
		"code":     {code},
		"state":    {"null"},
	}
	return s.baseURL + "/passport/v1/auth/httpsOauth2?" + params.Encode()
}

func (s *Session) interactiveHttpsOauth2(loginURL string) (string, error) {
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
	if err := validateHTTPSOauth2CallbackURL(callbackURL, s.baseHost); err != nil {
		return "", err
	}

	return callback, nil
}

func validateHTTPSOauth2CallbackURL(callbackURL *url.URL, baseHost string) error {
	if callbackURL.Scheme != "https" {
		return fmt.Errorf("invalid callback url: scheme not https")
	}
	if callbackURL.Host != baseHost {
		return fmt.Errorf("invalid callback url: host not match")
	}
	if callbackURL.Path != "/passport/v1/auth/httpsOauth2" {
		return fmt.Errorf("invalid callback url: path not match")
	}
	queries := callbackURL.Query()
	if queries.Get("code") == "" {
		return fmt.Errorf("invalid callback url: code not found")
	}
	return nil
}

func parsePortalTicketFromRedirect(redirectLocation, baseHost string) (string, error) {
	redirectURL, err := url.Parse(redirectLocation)
	if err != nil {
		return "", err
	}
	log.DebugPrintf("Received redirect: %s", redirectURL.String())
	if redirectURL.Scheme != "https" {
		return "", fmt.Errorf("invalid redirect url: scheme not https")
	}
	if redirectURL.Host != baseHost {
		return "", fmt.Errorf("invalid redirect url: host not match")
	}
	if redirectURL.Path != "/portal/shortcut.html" {
		return "", fmt.Errorf("invalid redirect url: path not match")
	}
	queries := redirectURL.Query()
	if queries.Get("data") == "" {
		return "", fmt.Errorf("invalid redirect url: data not found")
	}

	var tk struct {
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal([]byte(queries.Get("data")), &tk); err != nil {
		return "", err
	}
	log.DebugPrintf("Parsed portal data: %+v", tk)
	if tk.Ticket == "" {
		return "", fmt.Errorf("invalid portal data: ticket not found")
	}
	return tk.Ticket, nil
}

func (s *Session) httpsOauth2(callback string) error {
	log.Println("Perform GET /passport/v1/auth/httpsOauth2")

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
	log.DebugPrintf("Received httpsOauth2 data: %s", string(body))

	s.ticket = ticket
	return nil
}
