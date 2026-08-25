package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

func TestInteractiveCASUsesExternalLoginChallenge(t *testing.T) {
	session := NewSession("vpn.example.com", nil)
	session.challengeHandler = authchallenge.HandlerFuncs{
		ExternalLogin: func(challenge authchallenge.ExternalLoginChallenge) (authchallenge.ExternalLoginResponse, error) {
			if challenge.Kind != authchallenge.ExternalLoginCAS || challenge.LoginURL != "https://idp.example/login" {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.ExternalLoginResponse{
				CallbackURL: "https://vpn.example.com/passport/v1/auth/cas?ticket=cas-ticket",
			}, nil
		},
	}
	callback, err := session.interactiveCas("https://idp.example/login")
	if err != nil {
		t.Fatal(err)
	}
	if callback != "https://vpn.example.com/passport/v1/auth/cas?ticket=cas-ticket" {
		t.Fatalf("callback = %q", callback)
	}
}

func TestSecondarySMSUsesStructuredChallengeResponse(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/sms" || r.URL.Query().Get("action") != "checkcode" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		var payload struct {
			Code              string `json:"code"`
			SkipSecondaryAuth string `json:"skipSecondaryAuth"`
			AuthID            string `json:"authId"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		if payload.Code != "654321" || payload.SkipSecondaryAuth != "1" || payload.AuthID != "sms-id" {
			t.Errorf("unexpected payload: %+v", payload)
		}
		fmt.Fprint(w, `{"code":0,"data":{}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			if challenge.Kind != authchallenge.CodeSMS || !challenge.CanSkipSecondaryAuth {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.CodeResponse{Code: "654321", SkipSecondaryAuth: true}, nil
		},
	}
	step, err := session.smsCheckCode(authStep{Service: "auth/sms", AuthID: "sms-id", SMSMode: smsWithAuthID})
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestInteractiveOAuthUsesExternalLoginChallenge(t *testing.T) {
	session := NewSession("vpn.example.com", nil)
	session.challengeHandler = authchallenge.HandlerFuncs{
		ExternalLogin: func(challenge authchallenge.ExternalLoginChallenge) (authchallenge.ExternalLoginResponse, error) {
			if challenge.Kind != authchallenge.ExternalLoginOAuth2 || challenge.LoginURL != "https://idp.example/oauth" {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.ExternalLoginResponse{
				CallbackURL: "https://vpn.example.com/passport/v1/auth/httpsOauth2?code=oauth-code",
			}, nil
		},
	}
	callback, err := session.interactiveHttpsOauth2("https://idp.example/oauth")
	if err != nil {
		t.Fatal(err)
	}
	if callback != "https://vpn.example.com/passport/v1/auth/httpsOauth2?code=oauth-code" {
		t.Fatalf("callback = %q", callback)
	}
}
