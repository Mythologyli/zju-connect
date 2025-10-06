package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) authConfigImpl(params url.Values) (int, []AuthInfo, error) {
	log.Println("Perform GET /passport/v1/public/authConfig")

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
			PubKey             string     `json:"pubKey"`
			PubKeyExp          string     `json:"pubKeyExp"`
			AntiReplayRand     string     `json:"antiReplayRand"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, nil, err
	}
	log.DebugPrintf("Parsed auth config: %+v", re)

	s.csrfToken = re.Data.CSRF
	s.pubKey = re.Data.PubKey
	s.pubKeyExp = re.Data.PubKeyExp
	s.antiReplayRand = re.Data.AntiReplayRand

	return re.Data.IsLogin, re.Data.AuthServerInfoList, nil
}

func (s *Session) authConfigInit() (int, []AuthInfo, error) {
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
		"needTicket": {"1"},
	}

	return s.authConfigImpl(params)
}

func (s *Session) authConfigMod() (int, []AuthInfo, error) {
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
		"mod":        {"1"},
	}

	return s.authConfigImpl(params)
}

func (s *Session) reportEnv() error {
	log.Println("Perform POST /controller/v1/public/reportEnv")

	u := s.baseURL + "/controller/v1/public/reportEnv"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}

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
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(body))
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

func (s *Session) authCheck() (string, error) {
	log.Println("Perform GET /passport/v1/auth/authCheck")

	u := s.baseURL + "/passport/v1/auth/authCheck"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
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
	log.DebugPrintf("Received auth check: %s", string(body))

	var ac struct {
		Data struct {
			NextServiceList []struct {
				AuthId string `json:"authId"`
			} `json:"nextServiceList"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &ac)
	if err != nil {
		return "", err
	}
	log.DebugPrintf("Parsed auth check: %+v", ac)

	if len(ac.Data.NextServiceList) > 0 {
		return ac.Data.NextServiceList[0].AuthId, nil
	} else {
		return "", nil
	}
}

func (s *Session) sendSms(authId string) error {
	log.Println("Perform GET /passport/v1/auth/sms")
	u := s.baseURL + "/passport/v1/auth/sms"
	params := url.Values{
		"action":       {"sendsms"},
		"clientType":   {"SDPClient"},
		"platform":     {"Linux"},
		"lang":         {"en-US"},
		"isPrevEffect": {"0"},
		"taskId":       {""},
		"authId":       {authId},
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

	if re.Code != 0 {
		log.Printf("sendSms failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("sendSms failed with code %d: %s", re.Code, re.Message)
	}

	log.Printf("%s: %s", re.Message, re.Data.Tips)

	return nil
}

func (s *Session) smsCheckCode(authId string) error {
	log.Println("Perform POST /passport/v1/auth/sms")

	code := ""
	log.Print("Please enter the SMS verification code: ")
	_, err := fmt.Scanln(&code)
	if err != nil {
		return err
	}

	u := s.baseURL + "/passport/v1/auth/sms"
	params := url.Values{
		"action":     {"checkcode"},
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
	payload := map[string]interface{}{
		"isPrevEffect":      false,
		"code":              code,
		"skipSecondaryAuth": "0",
		"taskId":            "",
		"authId":            authId,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
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
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received sms check: %s", string(body))

	var re struct {
		Code int `json:"code"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed sms check: %+v", re)

	if re.Code != 0 {
		log.Printf("smsCheckCode failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("smsCheckCode failed with code %d", re.Code)
	}

	return nil
}

func (s *Session) onlineInfo() error {
	log.Println("Perform GET /passport/v1/user/onlineInfo")

	u := s.baseURL + "/passport/v1/user/onlineInfo"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
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
	log.DebugPrintf("Received online info: %s", string(body))

	var re struct {
		Code int `json:"code"`
	}

	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed online info: %+v", re)

	if re.Code != 0 {
		log.Printf("onlineInfo failed with code %d: %s", re.Code, string(body))
		return fmt.Errorf("onlineInfo failed with code %d", re.Code)
	}

	return nil
}

func (s *Session) ClientResource() ([]byte, error) {
	log.Println("Perform POST /controller/v1/user/clientResource")

	u := s.baseURL + "/controller/v1/user/clientResource"
	params := url.Values{
		"clientType": {"SDPClient"},
		"platform":   {"Linux"},
		"lang":       {"en-US"},
	}
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
	req, _ := http.NewRequest("POST", u+"?"+params.Encode(), bytes.NewReader(bdy))
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
