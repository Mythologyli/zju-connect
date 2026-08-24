package auth

import "fmt"

type LoginMethodOptions struct {
	AuthType      string
	Username      string
	Password      string
	Phone         string
	Domain        string
	GraphCodeFile string
	CASTicket     string
	OAuth2Code    string
}

func NewLoginMethod(options LoginMethodOptions) (LoginMethod, error) {
	authType := options.AuthType
	if authType == "" {
		switch {
		case options.Username != "" && options.Password != "":
			authType = "auth/psw"
		case options.Phone != "":
			authType = "auth/smsCheckCode"
		}
	}

	switch authType {
	case "auth/psw":
		return PasswordLogin{
			Username:      options.Username,
			Password:      options.Password,
			Domain:        options.Domain,
			GraphCodeFile: options.GraphCodeFile,
		}, nil
	case "auth/cas":
		return CASLogin{
			Domain: options.Domain,
			Ticket: options.CASTicket,
		}, nil
	case "auth/httpsOauth2":
		return HTTPSOauth2Login{
			Domain: options.Domain,
			Code:   options.OAuth2Code,
		}, nil
	case "auth/smsCheckCode":
		return SMSLogin{
			Phone:         options.Phone,
			Domain:        options.Domain,
			GraphCodeFile: options.GraphCodeFile,
		}, nil
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("unsupported auth type: %s", authType)
	}
}
