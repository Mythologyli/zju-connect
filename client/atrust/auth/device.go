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

type QueryDeviceResult struct {
	SelfID        string `json:"selfId"`
	DeviceTrusted bool   `json:"deviceTrusted"`
}

func (s *Session) QueryDevice() (*QueryDeviceResult, error) {
	log.Println("Perform GET /passport/v1/security/queryDevice")

	u := s.baseURL + "/passport/v1/security/queryDevice"
	params := WithSharedParams(url.Values{
		"status": {"trust"}, // can be "trust" or "untrust" but no need
	})
	req, _ := http.NewRequest("GET", u+"?"+params.Encode(), nil)
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
	log.DebugPrintf("Received query device: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
		Data    struct {
			SelfID        string `json:"selfId"`
			DeviceTrusted bool   `json:"deviceTrusted"`
		} `json:"data"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return nil, err
	}
	log.DebugPrintf("Parsed query device: %+v", re)

	if re.Code != 0 {
		log.Printf("queryDevice failed with code %d: %s", re.Code, re.Message)
		return nil, fmt.Errorf("queryDevice failed with code %d: %s", re.Code, re.Message)
	}

	return &QueryDeviceResult{
		SelfID:        re.Data.SelfID,
		DeviceTrusted: re.Data.DeviceTrusted,
	}, nil
}

func (s *Session) TrustDevice(idList []string) error {
	log.Println("Perform POST /passport/v1/security/trustDevice")

	u := s.baseURL + "/passport/v1/security/trustDevice"
	payload := map[string]interface{}{
		"idList": idList,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
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
	log.DebugPrintf("Received trust device: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed trust device: %+v", re)

	if re.Code != 0 {
		log.Printf("trustDevice failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("trustDevice failed with code %d: %s", re.Code, re.Message)
	}

	return nil
}

func (s *Session) UntrustDevice(idList []string) error {
	log.Println("Perform POST /passport/v1/security/untrustDevice")

	u := s.baseURL + "/passport/v1/security/untrustDevice"
	payload := map[string]interface{}{
		"idList": idList,
	}
	bdy, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", u+"?"+WithSharedParams(nil).Encode(), bytes.NewReader(bdy))
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
	log.DebugPrintf("Received untrust device: %s", string(body))

	var re struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	err = json.Unmarshal(body, &re)
	if err != nil {
		return err
	}
	log.DebugPrintf("Parsed untrust device: %+v", re)

	if re.Code != 0 {
		log.Printf("untrustDevice failed with code %d: %s", re.Code, re.Message)
		return fmt.Errorf("untrustDevice failed with code %d: %s", re.Code, re.Message)
	}

	return nil
}
