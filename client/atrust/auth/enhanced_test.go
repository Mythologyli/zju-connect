package auth

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRadiusChallengeEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/challenge" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/enhancedDone"}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.username = "user"
	step, err := session.submitTokenAt("auth/challenge", map[string]interface{}{
		"username": "user", "radiusToken": "123456", "skipSecondaryAuth": 0,
	})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/enhancedDone" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestEnhancedAuthStepEndpoint(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/passport/v1/auth/preEnhancedAuth" {
			t.Errorf("unexpected enhanced request: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Query().Get("authId") != "pre-id" {
			t.Errorf("missing enhanced authId: %s", r.URL.RawQuery)
		}
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/bindAuthDevice","nextServiceList":[{"authId":"bind-id","authType":"auth/bindAuthDevice"}]}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	step, err := session.completeEnhancedAuth(authStep{Service: "auth/preEnhancedAuth", AuthID: "pre-id"})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/bindAuthDevice" || step.AuthID != "bind-id" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}
