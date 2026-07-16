package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) completeCustomSMS() (authStep, error) {
	if err := s.sendCustomSMS(); err != nil {
		return authStep{}, err
	}

	code := ""
	log.Println("Tips: Add prefix '$' to sms code to skip secondary authentication")
	log.Print("Please enter the SMS verification code: ")
	if _, err := fmt.Scanln(&code); err != nil {
		return authStep{}, err
	}

	code, skipSecondaryAuth := strings.CutPrefix(code, "$")
	return s.customSMSCheckCode(code, skipSecondaryAuth)
}

func (s *Session) sendCustomSMS() error {
	log.Println("Perform POST /passport/v1/auth/customSms")

	payload := struct {
		IsPrevEffect string `json:"isPrevEffect"`
		TaskID       string `json:"taskId"`
	}{
		IsPrevEffect: "0",
		TaskID:       "",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	u := s.baseURL + "/passport/v1/auth/customSms"
	params := WithSharedParams(url.Values{
		"action": {"sendcustomsms"},
	})
	req, err := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	s.setAuthJSONHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.DebugPrintf("Received custom SMS send response: %s", string(body))

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return err
	}
	if result.Code != 0 {
		return fmt.Errorf("sendCustomSMS failed with code %d: %s", result.Code, result.Message)
	}

	log.Printf("%s: %s", result.Message, result.Data.Tips)
	return nil
}

func (s *Session) customSMSCheckCode(code string, skipSecondaryAuth bool) (authStep, error) {
	log.Println("Perform POST /passport/v1/auth/customSms")

	skipSecondaryAuthStr := "0"
	if skipSecondaryAuth {
		skipSecondaryAuthStr = "1"
	}

	payload := struct {
		IsPrevEffect      bool   `json:"isPrevEffect"`
		CustomCode        string `json:"customCode"`
		SkipSecondaryAuth string `json:"skipSecondaryAuth"`
		TaskID            string `json:"taskId"`
	}{
		IsPrevEffect:      false,
		CustomCode:        code,
		SkipSecondaryAuth: skipSecondaryAuthStr,
		TaskID:            "",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return authStep{}, err
	}

	u := s.baseURL + "/passport/v1/auth/customSms"
	params := WithSharedParams(url.Values{
		"action": {"checkcustomcode"},
	})
	req, err := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(body))
	if err != nil {
		return authStep{}, err
	}
	s.setAuthJSONHeaders(req)

	resp, err := s.client.Do(req)
	if err != nil {
		return authStep{}, err
	}
	defer resp.Body.Close()

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Received custom SMS check response: %s", string(body))

	var result struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return authStep{}, err
	}
	if result.Code != 0 {
		return authStep{}, fmt.Errorf("customSMSCheckCode failed with code %d: %s", result.Code, result.Message)
	}

	return authStepFromData(result.Data), nil
}

func (s *Session) setAuthJSONHeaders(req *http.Request) {
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())
}
