package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/log"
	"github.com/pquerna/otp/totp"
)

type tokenResponse struct {
	Code    int          `json:"code"`
	Message string       `json:"message"`
	Data    authStepData `json:"data"`
}

func (s *Session) completeTOTP() (authStep, error) {
	response := authchallenge.CodeResponse{}
	if s.totpSecret != "" {
		var err error
		response.Code, err = totp.GenerateCode(s.totpSecret, time.Now())
		if err != nil {
			return authStep{}, fmt.Errorf("generate TOTP token: %w", err)
		}
	} else {
		challenge := authchallenge.CodeChallenge{
			Kind:                 authchallenge.CodeTOTP,
			Message:              "Please enter the TOTP token:",
			CanSkipSecondaryAuth: true,
		}
		var err error
		response, err = s.challengeHandler.HandleCodeChallenge(challenge)
		if err != nil {
			return authStep{}, fmt.Errorf("complete TOTP challenge: %w", err)
		}
	}

	payload := map[string]interface{}{
		"action":            "auth",
		"totpToken":         response.Code,
		"isPrevEffect":      false,
		"skipSecondaryAuth": boolToInt(response.SkipSecondaryAuth),
	}
	s.addUsername(payload)
	return s.submitToken(payload)
}

func (s *Session) completeRadius(service string) (authStep, error) {
	challenge := authchallenge.CodeChallenge{
		Kind:                 authchallenge.CodeRadius,
		Message:              "Please enter the RADIUS token:",
		CanSkipSecondaryAuth: true,
	}
	response, err := s.challengeHandler.HandleCodeChallenge(challenge)
	if err != nil {
		return authStep{}, fmt.Errorf("complete RADIUS challenge: %w", err)
	}
	payload := map[string]interface{}{
		"radiusToken":       response.Code,
		"skipSecondaryAuth": boolToInt(response.SkipSecondaryAuth),
	}
	s.addUsername(payload)
	return s.submitTokenAt(service, payload)
}

func (s *Session) addUsername(payload map[string]interface{}) {
	if s.username != "" {
		payload["username"] = s.username
	}
}

func boolToInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func (s *Session) submitToken(payload map[string]interface{}) (authStep, error) {
	return s.submitTokenAt("auth/token", payload)
}

func (s *Session) submitTokenAt(service string, payload map[string]interface{}) (authStep, error) {
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
