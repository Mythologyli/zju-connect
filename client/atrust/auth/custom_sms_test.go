package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newCustomSMSTestSession(t *testing.T, handler http.HandlerFunc) *Session {
	t.Helper()

	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)

	session := NewSession("unused.invalid")
	session.baseURL = server.URL
	session.client = server.Client()
	session.csrfToken = "test-csrf-token"
	return session
}

func TestSendCustomSMSMatchesGatewayRequest(t *testing.T) {
	session := newCustomSMSTestSession(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/passport/v1/auth/customSms" {
			t.Errorf("path = %s, want /passport/v1/auth/customSms", r.URL.Path)
		}
		if got := r.URL.Query().Get("action"); got != "sendcustomsms" {
			t.Errorf("action = %q, want sendcustomsms", got)
		}
		assertSharedParams(t, r)
		if got := r.Header.Get("x-csrf-token"); got != "test-csrf-token" {
			t.Errorf("x-csrf-token = %q, want test-csrf-token", got)
		}

		var payload struct {
			IsPrevEffect string `json:"isPrevEffect"`
			TaskID       string `json:"taskId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if payload.IsPrevEffect != "0" || payload.TaskID != "" {
			t.Errorf("unexpected payload: %+v", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"sent","data":{"tips":"masked phone"}}`))
	})

	if err := session.sendCustomSMS(); err != nil {
		t.Fatalf("sendCustomSMS returned error: %v", err)
	}
}

func TestCustomSMSCheckCodeMatchesGatewayRequest(t *testing.T) {
	session := newCustomSMSTestSession(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/passport/v1/auth/customSms" {
			t.Errorf("path = %s, want /passport/v1/auth/customSms", r.URL.Path)
		}
		if got := r.URL.Query().Get("action"); got != "checkcustomcode" {
			t.Errorf("action = %q, want checkcustomcode", got)
		}
		assertSharedParams(t, r)

		var payload struct {
			IsPrevEffect      bool   `json:"isPrevEffect"`
			CustomCode        string `json:"customCode"`
			SkipSecondaryAuth string `json:"skipSecondaryAuth"`
			TaskID            string `json:"taskId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		if payload.IsPrevEffect || payload.CustomCode != "123456" || payload.SkipSecondaryAuth != "0" || payload.TaskID != "" {
			t.Errorf("unexpected payload: %+v", payload)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":0,"message":"verified","data":{"nextService":"auth/authCheck"}}`))
	})

	step, err := session.customSMSCheckCode("123456")
	if err != nil {
		t.Fatalf("customSMSCheckCode returned error: %v", err)
	}
	if step.Service != "auth/authCheck" {
		t.Fatalf("next service = %q, want auth/authCheck", step.Service)
	}
}

func TestCustomSMSCheckCodeRejectsGatewayError(t *testing.T) {
	session := newCustomSMSTestSession(t, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":1234,"message":"invalid code","data":{}}`))
	})

	if _, err := session.customSMSCheckCode("bad-code"); err == nil {
		t.Fatal("customSMSCheckCode returned nil error for a rejected code")
	}
}

func assertSharedParams(t *testing.T, r *http.Request) {
	t.Helper()
	query := r.URL.Query()
	if query.Get("clientType") != "SDPClient" || query.Get("platform") != "Linux" || query.Get("lang") != "en-US" {
		t.Errorf("unexpected shared params: %s", query.Encode())
	}
}
