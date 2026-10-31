package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/mythologyli/zju-connect/client/authchallenge"
	"github.com/mythologyli/zju-connect/log"
)

type bindAuthDeviceResponse struct {
	Code    int                `json:"code"`
	Message string             `json:"message"`
	Data    bindAuthDeviceData `json:"data"`
}

type bindAuthDeviceData struct {
	authStepData
	BindStatus        int                 `json:"bindStatus"`
	CurBindNum        int                 `json:"curBindNum"`
	BindNumLimit      int                 `json:"bindNumLimit"`
	TrustedDeviceList []trustedDeviceInfo `json:"trustedDeviceList"`
}

type trustedDeviceInfo struct {
	ID         string `json:"id"`
	DeviceName string `json:"deviceName"`
	DeviceType string `json:"deviceType"`
	OS         string `json:"os"`
	BindTime   string `json:"bindTime"`
}

func (s *Session) bindAuthDevice() (authStep, error) {
	result, err := s.requestBindAuthDevice("[]")
	if err != nil {
		return authStep{}, err
	}
	if result.Data.BindStatus != 1 {
		return authStepFromData(result.Data.authStepData), nil
	}
	if len(result.Data.TrustedDeviceList) == 0 {
		return authStep{}, fmt.Errorf("bindAuthDevice needs a trusted device unbound, but the server sent no trustedDeviceList")
	}

	need := max(1, result.Data.CurBindNum-result.Data.BindNumLimit+1)

	var message strings.Builder
	if result.Message != "" {
		fmt.Fprintf(&message, "%s\n", result.Message)
	}
	for i, device := range result.Data.TrustedDeviceList {
		name := device.DeviceName
		if name == "" {
			name = device.ID
		}
		fmt.Fprintf(&message, "%d) %s  os=%s  type=%s  bindTime=%s\n", i+1, name, device.OS, device.DeviceType, device.BindTime)
	}
	fmt.Fprintf(&message, "Trusted devices: %d/%d, enter %d number(s) to unbind, comma separated:", result.Data.CurBindNum, result.Data.BindNumLimit, need)

	response, err := s.challengeHandler.HandleCodeChallenge(authchallenge.CodeChallenge{
		Kind:    authchallenge.CodeDevice,
		Message: message.String(),
	})
	if err != nil {
		return authStep{}, fmt.Errorf("complete trusted device challenge: %w", err)
	}

	numbers := strings.Split(response.Code, ",")
	if len(numbers) != need {
		return authStep{}, fmt.Errorf("need %d trusted device number(s), got %d", need, len(numbers))
	}
	unbindIDs := make([]string, 0, need)
	for _, number := range numbers {
		index, err := strconv.Atoi(strings.TrimSpace(number))
		if err != nil || index < 1 || index > len(result.Data.TrustedDeviceList) {
			return authStep{}, fmt.Errorf("invalid trusted device number %q", number)
		}
		unbindIDs = append(unbindIDs, result.Data.TrustedDeviceList[index-1].ID)
	}
	unbindList, err := json.Marshal(unbindIDs)
	if err != nil {
		return authStep{}, err
	}

	result, err = s.requestBindAuthDevice(string(unbindList))
	if err != nil {
		return authStep{}, err
	}
	return authStepFromData(result.Data.authStepData), nil
}

func (s *Session) requestBindAuthDevice(unbindList string) (bindAuthDeviceResponse, error) {
	log.Println("Perform POST /passport/v1/auth/bindAuthDevice")

	body, err := json.Marshal(map[string]string{
		"unbindList": unbindList,
		"reason":     "",
	})
	if err != nil {
		return bindAuthDeviceResponse{}, err
	}
	u := s.baseURL + "/passport/v1/auth/bindAuthDevice?" + WithSharedParams(nil).Encode()
	req, err := http.NewRequest(http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return bindAuthDeviceResponse{}, err
	}
	s.setAuthJSONHeaders(req)

	resp, err := s.request(req)
	if err != nil {
		return bindAuthDeviceResponse{}, err
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return bindAuthDeviceResponse{}, err
	}
	log.DebugPrintf("Received bindAuthDevice: %s", string(responseBody))

	var result bindAuthDeviceResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return bindAuthDeviceResponse{}, err
	}
	if result.Code != 0 {
		return bindAuthDeviceResponse{}, fmt.Errorf("bindAuthDevice failed with code %d: %s", result.Code, result.Message)
	}
	return result, nil
}
