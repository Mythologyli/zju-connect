package auth

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) authConfig(mod, needTicket bool) (int, []AuthInfo, error) {
	log.Println("Perform GET /passport/v1/public/authConfig")

	params := WithSharedParams(nil)
	if mod {
		params.Set("mod", "1")
	}
	if needTicket {
		params.Set("needTicket", "1")
	}

	u := s.baseURL + "/passport/v1/public/authConfig"
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}

	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received auth config: %s", string(body))

	var re struct {
		Data struct {
			AuthServerInfoList []AuthInfo `json:"authServerInfoList"`
			IsLogin            int        `json:"isLogin"`
			CSRF               string     `json:"csrfToken"`
			Security           struct {
				CSRF string `json:"csrfToken"`
			} `json:"security"`
			PubKey         string             `json:"pubKey"`
			PubKeyExp      string             `json:"pubKeyExp"`
			AntiReplayRand string             `json:"antiReplayRand"`
			AntiMITM       antiMITMAttackData `json:"antiMITMAttackData"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, nil, err
	}
	log.DebugPrintf("Parsed auth config: %+v", re)
	responseCSRFToken := re.Data.CSRF
	if responseCSRFToken == "" {
		responseCSRFToken = re.Data.Security.CSRF
	}
	if !s.insecureSkipVerify && len(re.Data.AntiMITM.raw) != 0 {
		if err := verifySangforChallenge(re.Data.AntiMITM); err != nil {
			return 0, nil, err
		}
		if err := verifySangforMITMSignature(re.Data.AntiMITM); err != nil {
			return 0, nil, err
		}
		if re.Data.AntiMITM.Enable == 1 {
			if resp.TLS == nil {
				return 0, nil, fmt.Errorf("aTrust anti-MITM verification failed: response was not received over TLS")
			}
			if err := verifySangforCertificateIdentity(resp.TLS.PeerCertificates, re.Data.AntiMITM); err != nil {
				return 0, nil, err
			}
			if !re.Data.AntiMITM.AntiMITMRequest {
				if err := s.performAntiMITMRequest(re.Data.AntiMITM, responseCSRFToken); err != nil {
					return 0, nil, err
				}
			}
		}
	}

	s.csrfToken = responseCSRFToken
	s.pubKey = re.Data.PubKey
	s.pubKeyExp = re.Data.PubKeyExp
	s.antiReplayRand = re.Data.AntiReplayRand

	return re.Data.IsLogin, re.Data.AuthServerInfoList, nil
}

func (s *Session) performAntiMITMRequest(data antiMITMAttackData, csrfToken string) error {
	if data.Ticket == "" {
		return fmt.Errorf("aTrust anti-MITM request failed: server ticket is empty")
	}
	nonce, err := sangforNonce()
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: generate nonce: %w", err)
	}
	payload, err := json.Marshal(struct {
		Nonce  string `json:"nonce"`
		Ticket string `json:"ticket"`
	}{Nonce: nonce, Ticket: data.Ticket})
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: %w", err)
	}

	params := WithSharedParams(nil)
	if s.deviceID != "" {
		params.Set("mobileId", s.deviceID)
	}
	u := s.baseURL + "/controller/v1/public/antiMITMRequest"
	req, err := http.NewRequest(http.MethodPost, u+"?"+params.Encode(), bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-csrf-token", csrfToken)
	req.Header.Set("x-sdp-rid", s.rid)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: %w", err)
	}

	var result struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Nonce          string `json:"nonce"`
			AntiMITMEnable int    `json:"antiMITMEnable"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("aTrust anti-MITM request failed: invalid response: %w", err)
	}
	if result.Data.Nonce != nonce {
		return fmt.Errorf("aTrust anti-MITM request nonce mismatch")
	}
	if result.Code == 10000004 {
		return fmt.Errorf("aTrust anti-MITM request denied: session not found")
	}
	if result.Code == 10000008 {
		return fmt.Errorf("aTrust anti-MITM request detected a MITM attack")
	}

	expected := sangforHMAC(sangforSignatureKey(data), body)
	actual := strings.ToUpper(resp.Header.Get("X-Response-Sig"))
	if subtle.ConstantTimeCompare([]byte(actual), []byte(expected)) != 1 {
		return fmt.Errorf("aTrust anti-MITM response signature mismatch")
	}
	return nil
}

func (s *Session) reportEnv() error {
	log.Println("Perform POST /controller/v1/public/reportEnv")

	u := s.baseURL + "/controller/v1/public/reportEnv"

	if s.ticket == "" {
		return fmt.Errorf("ticket is empty")
	}

	payload := map[string]interface{}{
		"ticket":   s.ticket,
		"deviceId": s.deviceID,
		"env": map[string]interface{}{
			"endpoint": map[string]interface{}{
				"device_id": s.deviceID,
				"device": map[string]interface{}{
					"type": "browser",
				},
			},
		},
	}
	body, _ := json.Marshal(payload)
	log.DebugPrintf("Sending report env: %s", string(body))
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(body))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ = io.ReadAll(resp.Body)
	log.DebugPrintf("Received report env: %s", string(body))

	var re struct {
		Code int `json:"code"`
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed report env: %+v", re)

	if re.Code != 0 {
		log.Printf("reportEnv failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("reportEnv failed with code %d", re.Code)
	}

	return nil
}

type smsMode uint8

const (
	smsModeUnknown smsMode = iota
	smsWithoutAuthID
	smsWithAuthID
)

type authServiceInfo struct {
	AuthID   string `json:"authId"`
	AuthType string `json:"authType"`
}

type authStepData struct {
	NextService     string            `json:"nextService"`
	NextServiceList []authServiceInfo `json:"nextServiceList"`
}

type authStep struct {
	Service string
	AuthID  string
	SMSMode smsMode
}

func authStepFromData(data authStepData) authStep {
	step := authStep{Service: data.NextService}

	var selected *authServiceInfo
	for i := range data.NextServiceList {
		service := &data.NextServiceList[i]
		if step.Service != "" && service.AuthType == step.Service {
			selected = service
			break
		}
	}
	if selected == nil && len(data.NextServiceList) > 0 {
		selected = &data.NextServiceList[0]
	}

	if selected != nil {
		step.AuthID = selected.AuthID
		if step.Service == "" {
			step.Service = selected.AuthType
		} else if step.Service == "auth/token" {
			switch selected.AuthType {
			case "auth/totp", "auth/radius", "auth/challenge":
				step.Service = selected.AuthType
			}
		}
	}

	if step.Service == "auth/sendSms" {
		step.Service = "auth/sms"
	}

	// Some older gateways omit authType and only return an authId. This was
	// historically the response shape for SMS secondary authentication.
	if step.Service == "" && step.AuthID != "" {
		step.Service = "auth/sms"
	}

	if step.Service == "auth/sms" {
		if step.AuthID == "" {
			step.SMSMode = smsWithoutAuthID
		} else {
			step.SMSMode = smsWithAuthID
		}
	}

	return step
}

func (s *Session) authCheck() (authStep, error) {
	log.Println("Perform GET /passport/v1/auth/authCheck")

	u := s.baseURL + "/passport/v1/auth/authCheck"
	req, _ := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return authStep{}, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received auth check: %s", string(body))

	var ac struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	err = json.Unmarshal(body, &ac)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Parsed auth check: %+v", ac)

	if ac.Code != 0 {
		return authStep{}, fmt.Errorf("authCheck failed with code %d: %s", ac.Code, ac.Message)
	}

	return authStepFromData(ac.Data), nil
}

func (s *Session) phoneNumber(authID string) ([]string, error) {
	log.Println("Perform GET /passport/v1/public/phoneNumber")

	u := s.baseURL + "/passport/v1/public/phoneNumber"
	params := WithSharedParams(nil)
	if authID != "" {
		params.Set("authId", authID)
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			PhoneNumber         json.RawMessage `json:"phoneNumber"`
			MaskIdentifierValue string          `json:"maskIdentifierValue"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &re); err != nil {
		return nil, err
	}
	if re.Code != 0 {
		return nil, fmt.Errorf("phoneNumber failed with code %d: %s", re.Code, re.Message)
	}

	phoneNumbers, err := parsePhoneNumbers(re.Data.PhoneNumber)
	if err != nil {
		return nil, err
	}
	if len(phoneNumbers) == 0 && re.Data.MaskIdentifierValue != "" {
		phoneNumbers = append(phoneNumbers, re.Data.MaskIdentifierValue)
	}
	return phoneNumbers, nil
}

func parsePhoneNumbers(raw json.RawMessage) ([]string, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return nil, nil
	}

	if raw[0] == '[' {
		var phoneNumbers []string
		if err := json.Unmarshal(raw, &phoneNumbers); err != nil {
			return nil, fmt.Errorf("parse phoneNumber list: %w", err)
		}
		return phoneNumbers, nil
	}

	var phoneNumber string
	if err := json.Unmarshal(raw, &phoneNumber); err != nil {
		return nil, fmt.Errorf("parse phoneNumber: %w", err)
	}
	if phoneNumber == "" {
		return nil, nil
	}
	return []string{phoneNumber}, nil
}

func (s *Session) authSms(step authStep) error {
	log.Println("Perform GET /passport/v1/auth/sms")
	u := s.baseURL + "/passport/v1/auth/sms"
	params := WithSharedParams(url.Values{
		"action": {"sendsms"},
	})
	switch step.SMSMode {
	case smsWithAuthID:
		if step.AuthID == "" {
			return fmt.Errorf("SMS authentication requires authId")
		}
		params.Set("isPrevEffect", "0")
		params.Set("taskId", "")
		params.Set("authId", step.AuthID)
	case smsWithoutAuthID:
		// The stateful SMS flow does not use authId.
	default:
		return fmt.Errorf("unknown SMS authentication mode")
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received send sms: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips string `json:"tips"`
		}
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed send sms: %+v", re)

	if re.Code != 0 && re.Code != 75500401 {
		log.Printf("authSms failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("authSms failed with code %d: %s", re.Code, re.Message)
	}

	log.Printf("%s: %s", re.Message, re.Data.Tips)

	return nil
}

func (s *Session) smsCheckCode(step authStep) (authStep, error) {
	log.Println("Perform POST /passport/v1/auth/sms")

	code := ""
	log.Println("Tips: Add prefix '$' to sms code to skip secondary authentication")
	log.Print("Please enter the SMS verification code: ")
	_, err := fmt.Scanln(&code)
	if err != nil {
		return authStep{}, err
	}

	code, skipSecondaryAuth := strings.CutPrefix(code, "$")
	return s.secondarySMSCheckCodeImpl(step, code, skipSecondaryAuth)
}

func (s *Session) secondarySMSCheckCodeImpl(step authStep, code string, skipSecondaryAuth bool) (authStep, error) {
	u := s.baseURL + "/passport/v1/auth/sms"
	params := WithSharedParams(url.Values{
		"action": {"checkcode"},
	})

	skipSecondaryAuthStr := "0"
	if skipSecondaryAuth {
		skipSecondaryAuthStr = "1"
	}

	var req *http.Request
	switch step.SMSMode {
	case smsWithoutAuthID:
		form := url.Values{
			"code":              {code},
			"skipSecondaryAuth": {skipSecondaryAuthStr},
		}
		req, _ = http.NewRequest("POST", u+"?"+params.Encode(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case smsWithAuthID:
		if step.AuthID == "" {
			return authStep{}, fmt.Errorf("SMS authentication requires authId")
		}
		payload := map[string]any{
			"isPrevEffect":      false,
			"code":              code,
			"skipSecondaryAuth": skipSecondaryAuthStr,
			"taskId":            "",
			"authId":            step.AuthID,
		}
		bdy, _ := json.Marshal(payload)
		req, _ = http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
		req.Header.Set("Content-Type", "application/json;charset=utf-8")
	default:
		return authStep{}, fmt.Errorf("unknown SMS authentication mode")
	}
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return authStep{}, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received sms check: %s", string(body))

	var re struct {
		Code    int          `json:"code"`
		Message string       `json:"message"`
		Data    authStepData `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return authStep{}, err
	}
	log.DebugPrintf("Parsed sms check: %+v", re)

	if re.Code != 0 {
		log.Printf("smsCheckCode failed with code %d: %s", re.Code, string(body))
		return authStep{}, fmt.Errorf("smsCheckCode failed with code %d: %s", re.Code, re.Message)
	}

	return authStepFromData(re.Data), nil
}

func (s *Session) onlineInfo() (string, error) {
	log.Println("Perform GET /passport/v1/user/onlineInfo")

	u := s.baseURL + "/passport/v1/user/onlineInfo"
	req, _ := http.NewRequest("GET", u+"?"+WithSharedParams(nil).Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received online info: %s", string(body))

	var re struct {
		Code int `json:"code"`
		Data struct {
			Username string `json:"username"`
		}
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return "", err
	}
	log.DebugPrintf("Parsed online info: %+v", re)

	if re.Code != 0 {
		log.Printf("onlineInfo failed with code %d: %s", re.Code, string(body))
		return "", fmt.Errorf("onlineInfo failed with code %d", re.Code)
	}

	return re.Data.Username, nil
}

func (s *Session) ClientResource() ([]byte, error) {
	log.Println("Perform POST /controller/v1/user/clientResource")

	u := s.baseURL + "/controller/v1/user/clientResource"
	payload := map[string]interface{}{
		"resourceType": map[string]interface{}{
			"sdpPolicy":       struct{}{},
			"appList":         struct{}{},
			"favoriteAppList": struct{}{},
			"featureCenter":   struct{}{},
			"uemSpace": map[string]interface{}{
				"params": map[string]string{"action": "login"},
			},
		},
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received client resource: %s", string(body))

	return body, nil
}

func (s *Session) checkCode() ([]byte, error) {
	log.Println("Perform GET /passport/v1/public/checkCode")

	u := s.baseURL + "/passport/v1/public/checkCode"
	params := WithSharedParams(url.Values{
		"rnd": {strconv.FormatInt(time.Now().UnixMilli(), 10)},
	})
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Accept", "image/webp,image/apng,image/*,*/*;q=0.8")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received check code image: %d bytes", len(body))

	return body, nil
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
