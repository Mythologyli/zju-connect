package authchallenge

import (
	"fmt"
	"strings"
)

type CodeKind string

const (
	CodeSMS    CodeKind = "sms"
	CodeTOTP   CodeKind = "totp"
	CodeRadius CodeKind = "radius"
)

type CodeChallenge struct {
	Kind                 CodeKind
	Message              string
	CanSkipSecondaryAuth bool
}

type CodeResponse struct {
	Code              string
	SkipSecondaryAuth bool
}

type TextCaptchaChallenge struct {
	Image      []byte
	OutputPath string
	Message    string
}

type TextCaptchaResponse struct {
	Code string
}

func (TextCaptchaChallenge) Validate(response TextCaptchaResponse) error {
	if strings.TrimSpace(response.Code) == "" {
		return fmt.Errorf("captcha code is empty")
	}
	return nil
}

type Point struct {
	X int `json:"x"`
	Y int `json:"y"`
}

type ClickCaptchaChallenge struct {
	Image      []byte
	OutputPath string
	Message    string
}

type ClickCaptchaResponse struct {
	Points []Point
	Width  int
	Height int
}

type ExternalLoginKind string

const (
	ExternalLoginCAS    ExternalLoginKind = "cas"
	ExternalLoginOAuth2 ExternalLoginKind = "oauth2"
)

type ExternalLoginChallenge struct {
	Kind     ExternalLoginKind
	LoginURL string
	Message  string
}

type ExternalLoginResponse struct {
	CallbackURL string
}

type Handler interface {
	HandleCodeChallenge(CodeChallenge) (CodeResponse, error)
	HandleTextCaptcha(TextCaptchaChallenge) (TextCaptchaResponse, error)
	HandleClickCaptcha(ClickCaptchaChallenge) (ClickCaptchaResponse, error)
	HandleExternalLogin(ExternalLoginChallenge) (ExternalLoginResponse, error)
}

type HandlerFuncs struct {
	Code          func(CodeChallenge) (CodeResponse, error)
	TextCaptcha   func(TextCaptchaChallenge) (TextCaptchaResponse, error)
	ClickCaptcha  func(ClickCaptchaChallenge) (ClickCaptchaResponse, error)
	ExternalLogin func(ExternalLoginChallenge) (ExternalLoginResponse, error)
}

func (h HandlerFuncs) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	if h.Code == nil {
		return UnsupportedHandler{}.HandleCodeChallenge(challenge)
	}
	return h.Code(challenge)
}

func (h HandlerFuncs) HandleTextCaptcha(challenge TextCaptchaChallenge) (TextCaptchaResponse, error) {
	if h.TextCaptcha == nil {
		return UnsupportedHandler{}.HandleTextCaptcha(challenge)
	}
	return h.TextCaptcha(challenge)
}

func (h HandlerFuncs) HandleClickCaptcha(challenge ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	if h.ClickCaptcha == nil {
		return UnsupportedHandler{}.HandleClickCaptcha(challenge)
	}
	return h.ClickCaptcha(challenge)
}

func (h HandlerFuncs) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	if h.ExternalLogin == nil {
		return UnsupportedHandler{}.HandleExternalLogin(challenge)
	}
	return h.ExternalLogin(challenge)
}

type UnsupportedHandler struct{}

func (UnsupportedHandler) HandleCodeChallenge(challenge CodeChallenge) (CodeResponse, error) {
	return CodeResponse{}, fmt.Errorf("unsupported authentication code challenge: %s", challenge.Kind)
}

func (UnsupportedHandler) HandleTextCaptcha(TextCaptchaChallenge) (TextCaptchaResponse, error) {
	return TextCaptchaResponse{}, fmt.Errorf("unsupported text captcha challenge")
}

func (UnsupportedHandler) HandleClickCaptcha(ClickCaptchaChallenge) (ClickCaptchaResponse, error) {
	return ClickCaptchaResponse{}, fmt.Errorf("unsupported click captcha challenge")
}

func (UnsupportedHandler) HandleExternalLogin(challenge ExternalLoginChallenge) (ExternalLoginResponse, error) {
	return ExternalLoginResponse{}, fmt.Errorf("unsupported external login challenge: %s", challenge.Kind)
}
