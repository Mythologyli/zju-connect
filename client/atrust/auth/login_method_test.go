package auth

import (
	"reflect"
	"testing"
)

func TestNewLoginMethodTruthTable(t *testing.T) {
	passwordLogin := PasswordLogin{
		Username:      "user",
		Password:      "password",
		Domain:        "domain",
		GraphCodeFile: "graph-code.txt",
	}
	smsLogin := SMSLogin{
		Phone:         "13800000000",
		Domain:        "domain",
		GraphCodeFile: "graph-code.txt",
	}

	for _, tt := range []struct {
		name    string
		options LoginMethodOptions
		want    LoginMethod
		wantErr bool
	}{
		{
			name: "infer password",
			options: LoginMethodOptions{
				Username: "user", Password: "password", Domain: "domain", GraphCodeFile: "graph-code.txt",
			},
			want: passwordLogin,
		},
		{
			name: "password takes precedence over phone",
			options: LoginMethodOptions{
				Username: "user", Password: "password", Phone: "13800000000", Domain: "domain", GraphCodeFile: "graph-code.txt",
			},
			want: passwordLogin,
		},
		{
			name: "infer SMS",
			options: LoginMethodOptions{
				Phone: "13800000000", Domain: "domain", GraphCodeFile: "graph-code.txt",
			},
			want: smsLogin,
		},
		{
			name: "explicit password",
			options: LoginMethodOptions{
				AuthType: "auth/psw", Username: "user", Password: "password", Domain: "domain", GraphCodeFile: "graph-code.txt",
			},
			want: passwordLogin,
		},
		{
			name: "explicit CAS",
			options: LoginMethodOptions{
				AuthType: "auth/cas", Domain: "domain", CASTicket: "ticket",
			},
			want: CASLogin{Domain: "domain", Ticket: "ticket"},
		},
		{
			name: "explicit OAuth2",
			options: LoginMethodOptions{
				AuthType: "auth/httpsOauth2", Domain: "domain", OAuth2Code: "code",
			},
			want: HTTPSOauth2Login{Domain: "domain", Code: "code"},
		},
		{
			name: "explicit SMS",
			options: LoginMethodOptions{
				AuthType: "auth/smsCheckCode", Phone: "13800000000", Domain: "domain", GraphCodeFile: "graph-code.txt",
			},
			want: smsLogin,
		},
		{name: "no authentication"},
		{name: "unsupported authentication", options: LoginMethodOptions{AuthType: "unsupported"}, wantErr: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewLoginMethod(tt.options)
			if (err != nil) != tt.wantErr {
				t.Fatalf("error = %v, wantErr %t", err, tt.wantErr)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("login method = %#v, want %#v", got, tt.want)
			}
		})
	}
}
