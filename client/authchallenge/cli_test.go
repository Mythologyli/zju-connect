package authchallenge

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLIHandlerCodeChallenge(t *testing.T) {
	var output bytes.Buffer
	handler := NewCLIHandler(CLIOptions{
		Input:  strings.NewReader("$ 123456\n"),
		Output: &output,
	})
	challenge := CodeChallenge{
		Kind:                 CodeSMS,
		Message:              "SMS code:",
		CanSkipSecondaryAuth: true,
	}
	response, err := handler.HandleCodeChallenge(challenge)
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != "123456" || !response.SkipSecondaryAuth {
		t.Fatalf("unexpected response: %+v", response)
	}
	if !strings.Contains(output.String(), "SMS code:") || !strings.Contains(output.String(), "prefix '$'") {
		t.Fatalf("unexpected output: %q", output.String())
	}
}

func TestCLIHandlerReadsCompleteCallbackLine(t *testing.T) {
	handler := NewCLIHandler(CLIOptions{
		Input:  strings.NewReader("https://vpn.example/callback?code=a%20b\n"),
		Output: &bytes.Buffer{},
	})
	response, err := handler.HandleExternalLogin(ExternalLoginChallenge{
		Kind:     ExternalLoginOAuth2,
		LoginURL: "https://idp.example/login",
		Message:  "Callback URL:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.CallbackURL != "https://vpn.example/callback?code=a%20b" {
		t.Fatalf("callback URL = %q", response.CallbackURL)
	}
}

func TestCLIHandlerTextCaptcha(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captcha.png")
	handler := NewCLIHandler(CLIOptions{
		Input:  strings.NewReader("abcd\n"),
		Output: &bytes.Buffer{},
	})
	response, err := handler.HandleTextCaptcha(TextCaptchaChallenge{
		Image:      []byte("image"),
		OutputPath: path,
		Message:    "Captcha:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if response.Code != "abcd" {
		t.Fatalf("captcha code = %q", response.Code)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "image" {
		t.Fatalf("captcha image = %q", data)
	}
}

func TestCLIHandlerClickCaptchaJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "captcha.png")
	handler := NewCLIHandler(CLIOptions{
		Input:  strings.NewReader(`{"coordinates":[[11,22],[33,44]],"width":300,"height":150}` + "\n"),
		Output: &bytes.Buffer{},
	})
	response, err := handler.HandleClickCaptcha(ClickCaptchaChallenge{
		Image:      []byte("image"),
		OutputPath: path,
		Message:    "Captcha JSON:",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Points) != 2 || response.Points[0] != (Point{X: 11, Y: 22}) || response.Points[1] != (Point{X: 33, Y: 44}) || response.Width != 300 || response.Height != 150 {
		t.Fatalf("unexpected response: %+v", response)
	}
}

func TestParseClickCaptchaPointObjects(t *testing.T) {
	response, err := parseClickCaptchaResponse(`[{"x":100,"y":200},{"x":150,"y":300}]`)
	if err != nil {
		t.Fatal(err)
	}
	if len(response.Points) != 2 || response.Points[0] != (Point{X: 100, Y: 200}) || response.Points[1] != (Point{X: 150, Y: 300}) {
		t.Fatalf("unexpected points: %+v", response.Points)
	}
}

func TestParseClickCaptchaRejectsInvalidInput(t *testing.T) {
	if _, err := parseClickCaptchaResponse(`{"coordinates":"bad"}`); err == nil {
		t.Fatal("expected invalid click captcha response error")
	}
}
