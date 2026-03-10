package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/mythologyli/zju-connect/log"
)

func (s *Session) loginAuthSmsCheckCode(phone, loginDomain, graphCodeFile string) error {
	sendSmsProcess := func(graphCheckCode string) (int, error) {
		return s.sendSms(phone, loginDomain, graphCheckCode)
	}
	err := s.withGraphCheckCode(sendSmsProcess, graphCodeFile)
	if err != nil {
		return err
	}

	code := ""
	log.Print("Please enter the SMS verification code: ")
	_, err = fmt.Scanln(&code)
	if err != nil {
		return err
	}

	smsCheckCodeProcess := func(graphCheckCode string) (int, error) {
		return s.smsCheckCodeImpl(code, phone, loginDomain, graphCheckCode)
	}
	return s.withGraphCheckCode(smsCheckCodeProcess, graphCodeFile)
}

func (s *Session) sendSms(phone, loginDomain, graphCheckCode string) (int, error) {
	log.Println("Perform POST /passport/v1/public/sendSms")

	data := map[string]interface{}{
		"phone":          phone + "@" + loginDomain,
		"graphCheckCode": graphCheckCode,
	}

	postBody, _ := json.Marshal(data)

	u := s.baseURL + "/passport/v1/public/sendSms"
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(postBody))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received sendSms: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Tips                 string `json:"tips"`
			Interval             string `json:"interval"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, err
	}
	log.DebugPrintf("Parsed sendSms: %+v", re)
	if re.Code != 0 || re.Message != "" {
		log.Printf("Code: %d, Message: %s", re.Code, re.Message)
	}

	return re.Data.GraphCheckCodeEnable, nil
}

func (s *Session) smsCheckCodeImpl(code, phone, loginDomain, graphCheckCode string) (int, error) {
	log.Println("Perform POST /passport/v1/auth/smsCheckCode")

	data := map[string]interface{}{
		"code":  code,
		"phone": phone + "@" + loginDomain,
	}

	if graphCheckCode != "" {
		data["graphCheckCode"] = graphCheckCode
	}
	postBody, _ := json.Marshal(data)

	u := s.baseURL + "/passport/v1/auth/smsCheckCode"
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(postBody))
	req.Header.Set("User-Agent", UserAgent)
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	req.Header.Set("x-csrf-token", s.csrfToken)
	req.Header.Set("x-sdp-env", s.env)
	req.Header.Set("x-sdp-traceid", s.randSdpId())

	resp, err := s.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func(Body io.ReadCloser) {
		_ = Body.Close()
	}(resp.Body)
	body, _ := io.ReadAll(resp.Body)
	log.DebugPrintf("Received smsCheckCode: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			Ticket               string `json:"ticket"`
			GraphCheckCodeEnable int    `json:"graphCheckCodeEnable"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return 0, err
	}
	if re.Code != 0 || re.Message != "" {
		log.Printf("Code: %d, Message: %s", re.Code, re.Message)
	}
	log.DebugPrintf("Parsed smsCheckCode: %+v", re)

	s.ticket = re.Data.Ticket

	return re.Data.GraphCheckCodeEnable, nil
}
