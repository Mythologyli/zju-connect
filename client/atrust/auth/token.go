package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
	"github.com/pquerna/otp/totp"
)

type tokenResponse struct {
	Code    int          `json:"code"`
	Message string       `json:"message"`
	Data    authStepData `json:"data"`
}

func (s *Session) completeTOTP() (authStep, error) {
	token := ""
	if s.totpSecret != "" {
		var err error
		token, err = totp.GenerateCode(s.totpSecret, time.Now())
		if err != nil {
			return authStep{}, fmt.Errorf("generate TOTP token: %w", err)
		}
	} else {
		log.Print("Please enter the TOTP token: ")
		if _, err := fmt.Scanln(&token); err != nil {
			return authStep{}, err
		}
	}

	token, skipSecondaryAuth := parseTokenInput(token)
	return s.submitToken(map[string]interface{}{
		"username":          s.username,
		"action":            "auth",
		"totpToken":         token,
		"isPrevEffect":      false,
		"skipSecondaryAuth": skipSecondaryAuth,
	})
}

func (s *Session) completeRadius(service string) (authStep, error) {
	log.Print("Please enter the RADIUS token: ")
	token := ""
	if _, err := fmt.Scanln(&token); err != nil {
		return authStep{}, err
	}

	token, skipSecondaryAuth := parseTokenInput(token)
	return s.submitTokenAt(service, map[string]interface{}{
		"username":          s.username,
		"radiusToken":       token,
		"skipSecondaryAuth": skipSecondaryAuth,
	})
}

func parseTokenInput(input string) (string, int) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "$") {
		return strings.TrimSpace(strings.TrimPrefix(input, "$")), 1
	}
	return input, 0
}

func (s *Session) submitToken(payload map[string]interface{}) (authStep, error) {
	return s.submitTokenAt("auth/token", payload)
}

func (s *Session) submitTokenAt(service string, payload map[string]interface{}) (authStep, error) {
	if s.username == "" {
		return authStep{}, fmt.Errorf("username is empty for token authentication")
	}
	if service != "auth/token" && service != "auth/challenge" {
		return authStep{}, fmt.Errorf("unsupported token authentication service: %s", service)
	}

	postBody, err := json.Marshal(payload)
	if err != nil {
		return authStep{}, err
	}

	path := "/passport/v1/" + service
	log.Printf("Perform POST %s", path)
	u := s.baseURL + path
	req, err := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(postBody))
	if err != nil {
		return authStep{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received token authentication: %s", string(body))

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("token authentication failed with code %d: %s", result.Code, result.Message)
	}
	return authStepFromData(result.Data), nil
}

func (s *Session) accessCheck() (authStep, error) {
	log.Println("Perform GET /passport/v1/auth/accessCheck")
	u := s.baseURL + "/passport/v1/auth/accessCheck"
	req, err := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	if err != nil {
		return authStep{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received access check: %s", string(body))

	var result tokenResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("accessCheck failed with code %d: %s", result.Code, result.Message)
	}
	return authStepFromData(result.Data), nil
}
