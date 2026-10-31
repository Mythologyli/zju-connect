package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mythologyli/zju-connect/client/authchallenge"
)

func TestBindAuthDeviceUsesStructuredChallengeResponse(t *testing.T) {
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/bindAuthDevice" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		requests++
		var payload struct {
			UnbindList string `json:"unbindList"`
			Reason     string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Error(err)
		}
		switch requests {
		case 1:
			if payload.UnbindList != "[]" || payload.Reason != "" {
				t.Errorf("unexpected first payload: %+v", payload)
			}
			fmt.Fprint(w, `{"code":0,"data":{"bindStatus":1,"curBindNum":2,"bindNumLimit":2,"trustedDeviceList":[{"id":"device-a","deviceName":"laptop"},{"id":"device-b","deviceName":"desktop"}]}}`)
		case 2:
			if payload.UnbindList != `["device-a"]` || payload.Reason != "" {
				t.Errorf("unexpected second payload: %+v", payload)
			}
			fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/enhancedConfirm"}}`)
		default:
			t.Errorf("unexpected extra request")
		}
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			if challenge.Kind != authchallenge.CodeDevice || !strings.Contains(challenge.Message, "laptop") {
				t.Fatalf("unexpected challenge: %+v", challenge)
			}
			return authchallenge.CodeResponse{Code: "1"}, nil
		},
	}
	step, err := session.bindAuthDevice()
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/enhancedConfirm" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}

func TestBindAuthDeviceWithoutQuota(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/passport/v1/auth/bindAuthDevice" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.String())
		}
		fmt.Fprint(w, `{"code":0,"data":{"nextService":"auth/authCheck"}}`)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	session.challengeHandler = authchallenge.HandlerFuncs{
		Code: func(challenge authchallenge.CodeChallenge) (authchallenge.CodeResponse, error) {
			t.Fatalf("unexpected challenge: %+v", challenge)
			return authchallenge.CodeResponse{}, nil
		},
	}
	step, err := session.bindAuthDevice()
	if err != nil {
		t.Fatal(err)
	}
	if step.Service != "auth/authCheck" {
		t.Fatalf("unexpected next step: %+v", step)
	}
}
