package auth

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) loginAuthCas(loginUrl string) error {
	log.Printf("Visit %s to login, and catch the callback url", s.baseURL+loginUrl)
	log.Println("Please enter the callback url:")
	var callback string
	_, err := fmt.Scanln(&callback)
	if err != nil {
		return err
	}

	callbackURL, err := url.Parse(callback)
	if err != nil {
		return err
	}
	if callbackURL.Scheme != "https" {
		return fmt.Errorf("invalid callback url: scheme not https")
	}
	if callbackURL.Host != s.baseHost {
		return fmt.Errorf("invalid callback url: host not match")
	}
	if callbackURL.Path != "/passport/v1/auth/cas" {
		return fmt.Errorf("invalid callback url: path not match")
	}
	queries := callbackURL.Query()
	if queries.Get("sfDomain") != s.loginDomain {
		return fmt.Errorf("invalid callback url: login domain not match")
	}
	if queries.Get("ticket") == "" {
		return fmt.Errorf("invalid callback url: ticket not found")
	}

	err = s.cas(callback)
	if err != nil {
		return err
	}

	_, _, err = s.authConfigMod()
	return err
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
	if resp.StatusCode != 302 {
		return fmt.Errorf("invalid status code: %d", resp.StatusCode)
	}
	redirectURL, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return err
	}
	log.DebugPrintf("Received redirect: %s", redirectURL.String())
	if redirectURL.Scheme != "https" {
		return fmt.Errorf("invalid redirect url: scheme not https")
	}
	if redirectURL.Host != s.baseHost {
		return fmt.Errorf("invalid redirect url: host not match")
	}
	if redirectURL.Path != "/portal/shortcut.html" {
		return fmt.Errorf("invalid redirect url: path not match")
	}
	queries := redirectURL.Query()
	if queries.Get("data") == "" {
		return fmt.Errorf("invalid redirect url: data not found")
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received cas data: %s", string(body))

	var tk struct {
		Ticket string `json:"ticket"`
	}
	err = json.Unmarshal([]byte(queries.Get("data")), &tk)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed portal data: %+v", tk)

	if tk.Ticket == "" {
		return fmt.Errorf("invalid portal data: ticket not found")
	}
	s.ticket = tk.Ticket
	return nil
}
