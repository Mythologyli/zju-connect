package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAuthStepFromTokenService(t *testing.T) {
	step := authStepFromData(authStepData{
		NextService: "auth/token",
		NextServiceList: []authServiceInfo{{
			AuthID:   "totp-id",
			AuthType: "auth/totp",
		}},
	})
	if step.Service != "auth/totp" || step.AuthID != "totp-id" {
		t.Fatalf("unexpected token step: %+v", step)
	}

	step = authStepFromData(authStepData{NextService: "auth/sendSms"})
	if step.Service != "auth/sms" || step.SMSMode != smsWithoutAuthID {
		t.Fatalf("unexpected sendSms step: %+v", step)
	}
}

func TestParseTokenInput(t *testing.T) {
	token, skip := parseTokenInput(" $ 123456 ")
	if token != "123456" || skip != 1 {
		t.Fatalf("unexpected parsed token: token=%q skip=%d", token, skip)
	}
}

func TestSubmitTOTPToken(t *testing.T) {
	type requestPayload struct {
		Username          string `json:"username"`
		Action            string `json:"action"`
		TOTPToken         string `json:"totpToken"`
		IsPrevEffect      bool   `json:"isPrevEffect"`
		SkipSecondaryAuth int    `json:"skipSecondaryAuth"`
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/token" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var payload requestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Username != "user@domain" || payload.Action != "auth" || payload.TOTPToken != "123456" || payload.IsPrevEffect || payload.SkipSecondaryAuth != 0 {
			t.Errorf("unexpected payload: %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/accessCheck"}}`)
	}))
	defer server.Close()

	session := NewSession(strings.TrimPrefix(server.URL, "https://"))
	session.username = "user@domain"
	step, err := session.submitToken(map[string]interface{}{
		"username":          session.username,
		"action":            "auth",
		"totpToken":         "123456",
		"isPrevEffect":      false,
		"skipSecondaryAuth": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/accessCheck" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestAccessCheck(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/passport/v1/auth/accessCheck" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := NewSession(strings.TrimPrefix(server.URL, "https://"))
	step, err := session.accessCheck()
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}
