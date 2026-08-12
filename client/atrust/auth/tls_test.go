package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPinnedServerCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"data":{}}`))
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, err := session.accessCheck(); err != nil {
		t.Fatal(err)
	}
	if got := session.ServerCertificateSHA256(); len(got) != 64 {
		t.Fatalf("unexpected certificate fingerprint: %q", got)
	}
}

func TestPinnedServerCertificateMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	session := NewSessionWithOptions(
		strings.TrimPrefix(server.URL, "https://"),
		SessionOptions{ServerCertSHA256: strings.Repeat("00", 32)},
	)
	if _, err := session.accessCheck(); err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("expected fingerprint mismatch, got %v", err)
	}
}
func TestSangforCertificateDigest(t *testing.T) {
	rawDER := []byte{0x01, 0x02, 0x03}
	want := sha256.Sum256([]byte("AQID@~*&!()-"))
	if got := sangforCertificateDigest(rawDER); hex.EncodeToString(got) != hex.EncodeToString(want[:]) {
		t.Fatalf("unexpected Sangfor certificate digest: %x", got)
	}
}

func TestVerifySangforChallenge(t *testing.T) {
	data := antiMITMAttackData{
		Enable:             1,
		DevicePubKeyMod:    "A1B2C3",
		DevicePubKeyExp:    "10001",
		Challenge:          "challenge-vector",
		EncryptedChallenge: "E4E065E124F3E6FA5B5125745170A7EE97342BB9E9AE2FF7F523FF5872B9541E",
	}
	if err := verifySangforChallenge(data); err != nil {
		t.Fatal(err)
	}
}

func TestVerifySangforChallengeRejectsMismatch(t *testing.T) {
	data := antiMITMAttackData{
		Enable:             1,
		DevicePubKeyMod:    "A1B2C3",
		DevicePubKeyExp:    "10001",
		Challenge:          "challenge-vector",
		EncryptedChallenge: strings.Repeat("0", 64),
	}
	if err := verifySangforChallenge(data); err == nil || !strings.Contains(err.Error(), "challenge mismatch") {
		t.Fatalf("expected challenge mismatch, got %v", err)
	}
}

func TestSangforMITMSignatureVector(t *testing.T) {
	raw := []byte(`{"enable":1,"antiMITMRequest":false,"devicePubKeyMod":"A1B2C3","devicePubKeyExp":"10001","rsaCert":"CERT","sm2encCert":"SM","challenge":"challenge-vector","encryptedChallenge":"E4E065E124F3E6FA5B5125745170A7EE97342BB9E9AE2FF7F523FF5872B9541E","ticket":"ticket","mitmSig":"50f004a1d13224483296cd1b8c64af9e0ce8005e7e58ea056593a8baab2d57a8"}`)
	var data antiMITMAttackData
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	if err := verifySangforMITMSignature(data); err != nil {
		t.Fatal(err)
	}
}

func TestSangforNonceGeneratorVector(t *testing.T) {
	state := uint64(1)
	got := strings.ToUpper(hex.EncodeToString(sangforNonceBytes(&state, 16)))
	if want := "8EE1457CF0225058C27E226EAA4CA802"; got != want {
		t.Fatalf("unexpected Sangfor nonce sequence: got %s, want %s", got, want)
	}
}

func TestPerformAntiMITMRequest(t *testing.T) {
	data := antiMITMAttackData{
		DevicePubKeyMod: "A1B2C3",
		DevicePubKeyExp: "10001",
		Challenge:       "challenge-vector",
		Ticket:          "ticket",
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/controller/v1/public/antiMITMRequest" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("unexpected request: %s %q", r.Method, r.Header.Get("Content-Type"))
		}
		requestBody, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		var request struct {
			Nonce  string `json:"nonce"`
			Ticket string `json:"ticket"`
		}
		if err := json.Unmarshal(requestBody, &request); err != nil {
			t.Fatal(err)
		}
		if len(request.Nonce) != 64 || request.Ticket != data.Ticket {
			t.Fatalf("unexpected anti-MITM body: %+v", request)
		}
		expectedBody := fmt.Sprintf("\n            {\n                \"nonce\": \"%s\",\n                \"ticket\": \"%s\"\n            }\n        ", request.Nonce, request.Ticket)
		if string(requestBody) != expectedBody {
			t.Fatalf("unexpected anti-MITM body encoding: %q", requestBody)
		}
		body := []byte(fmt.Sprintf(`{"code":0,"data":{"nonce":%q,"antiMITMEnable":1}}`, request.Nonce))
		w.Header().Set("X-Response-Sig", sangforHMAC(sangforSignatureKey(data), body))
		_, _ = w.Write(body)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if err := session.performAntiMITMRequest(data, "csrf-token"); err != nil {
		t.Fatal(err)
	}
}

func TestPerformAntiMITMRequestRejectsResponseSignature(t *testing.T) {
	data := antiMITMAttackData{
		DevicePubKeyMod: "A1B2C3",
		DevicePubKeyExp: "10001",
		Challenge:       "challenge-vector",
		Ticket:          "ticket",
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Nonce string `json:"nonce"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatal(err)
		}
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"nonce":%q}}`, request.Nonce)
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if err := session.performAntiMITMRequest(data, ""); err == nil || !strings.Contains(err.Error(), "response signature mismatch") {
		t.Fatalf("expected response signature mismatch, got %v", err)
	}
}

func TestAuthConfigAcceptsMatchingAntiMITMCertificate(t *testing.T) {
	var encodedCertificate string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":%s}}`, signedAntiMITMJSON(t, 1, encodedCertificate, ""))
	}))
	defer server.Close()
	encodedCertificate = base64.StdEncoding.EncodeToString(server.Certificate().Raw)

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestAuthConfigReportsButDoesNotPropagateSecondStageFailure(t *testing.T) {
	var encodedCertificate string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/controller/v1/public/antiMITMRequest" {
			_, _ = w.Write([]byte(`{"code":0,"data":{"nonce":"wrong"}}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":%s}}`, signedAntiMITMJSONWithRequest(t, 1, encodedCertificate, "", false))
	}))
	defer server.Close()
	encodedCertificate = base64.StdEncoding.EncodeToString(server.Certificate().Raw)

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatalf("official authentication caller does not propagate the check result: %v", err)
	}
}

func TestAuthConfigReportsButDoesNotPropagateMismatchedAntiMITMCertificate(t *testing.T) {
	encodedCertificate := base64.StdEncoding.EncodeToString([]byte("not the peer certificate"))

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":%s}}`, signedAntiMITMJSON(t, 1, "", encodedCertificate))
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatalf("official authentication caller does not propagate the check result: %v", err)
	}
}

func TestAuthConfigDoesNotParseAdvertisedSM2Certificate(t *testing.T) {
	var encodedCertificate string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":%s}}`, signedAntiMITMJSON(t, 1, encodedCertificate, "not-base64"))
	}))
	defer server.Close()
	encodedCertificate = base64.StdEncoding.EncodeToString(server.Certificate().Raw)

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func TestAuthConfigIgnoresUnknownAntiMITMEnableValue(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintf(w, `{"code":0,"data":{"antiMITMAttackData":%s}}`, signedAntiMITMJSON(t, 2, "", ""))
	}))
	defer server.Close()

	session := newTLSTestSession(server)
	if _, _, err := session.authConfig(false, true); err != nil {
		t.Fatal(err)
	}
}

func signedAntiMITMJSON(t *testing.T, enable int, rsaCert, sm2EncCert string) string {
	return signedAntiMITMJSONWithRequest(t, enable, rsaCert, sm2EncCert, true)
}

func signedAntiMITMJSONWithRequest(t *testing.T, enable int, rsaCert, sm2EncCert string, antiMITMRequest bool) string {
	t.Helper()
	data := antiMITMAttackData{
		Enable:             enable,
		DevicePubKeyMod:    "A1B2C3",
		DevicePubKeyExp:    "10001",
		RSACert:            rsaCert,
		SM2EncCert:         sm2EncCert,
		Challenge:          "challenge-vector",
		EncryptedChallenge: "E4E065E124F3E6FA5B5125745170A7EE97342BB9E9AE2FF7F523FF5872B9541E",
		Ticket:             "ticket",
		AntiMITMRequest:    antiMITMRequest,
	}
	raw, err := json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	data.raw = raw
	data.MITMSignature, err = sangforMITMSignature(data)
	if err != nil {
		t.Fatal(err)
	}
	raw, err = json.Marshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
