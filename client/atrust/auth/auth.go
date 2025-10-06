package auth

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mathrand "math/rand"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const (
	UserAgent = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
)

type Cookie struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type ClientAuthData struct {
	Cookies      []Cookie `json:"cookies"`
	DeviceID     string   `json:"device_id"`
	ConnectionID string   `json:"connection_id"`
}

type Session struct {
	client   *http.Client
	deviceID string

	baseHost string
	baseURL  string

	rid            string
	env            string
	csrfToken      string
	pubKey         string
	pubKeyExp      string
	antiReplayRand string
	ticket         string

	response map[string]json.RawMessage
}

func NewSession(server string) *Session {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second}

	rid := base64.StdEncoding.EncodeToString([]byte(server))

	return &Session{
		client:   client,
		baseHost: server,
		baseURL:  "https://" + server,
		rid:      rid,
		response: make(map[string]json.RawMessage),
	}
}

type AuthInfo struct {
	LoginDomain string `json:"loginDomain"`
	AuthType    string `json:"authType"`
	AuthName    string `json:"authName"`
	LoginURL    string `json:"loginUrl"`
}

func (s *Session) randSdpId(n ...int) string {
	length := 8
	if len(n) > 0 {
		length = n[0]
	}
	hexes := make([]byte, length)
	for i := 0; i < length; i++ {
		hexes[i] = "0123456789abcdef"[mathrand.Intn(16)]
	}
	return string(hexes)
}

func (s *Session) Login(username, password, loginDomain, authType, deviceId, graphCodeFile, casTicket string, cookies []Cookie) (string, string, []Cookie, error) {
	sid := ""
	if len(cookies) > 0 {
		for _, cookie := range cookies {
			if cookie.Host == s.baseHost && cookie.Scheme == "https" && cookie.Name == "sid" {
				sid = cookie.Value
			}

			c := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			s.client.Jar.SetCookies(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme}, []*http.Cookie{c})
		}
	}

	s.deviceID = deviceId
	s.env = base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + deviceId + `"}`))

	isLogin, authInfoList, err := s.authConfigInit()
	if err != nil {
		return "", "", nil, err
	}
	if isLogin == 1 {
		log.Println("Already logged in")
		username, err := s.onlineInfo()
		return username, sid, cookies, err
	}

	var foundAuthInfo *AuthInfo
	for _, authInfo := range authInfoList {
		if authInfo.AuthType == authType && authInfo.LoginDomain == loginDomain {
			foundAuthInfo = &authInfo
			break
		}
	}
	if foundAuthInfo == nil {
		log.Printf("Available authentication methods: %+v", authInfoList)
		return "", "", nil, fmt.Errorf("not provided auth type: %s, login domain: %s", authType, loginDomain)
	}

	log.Printf("Starting login with auth type: %s, login domain: %s", authType, loginDomain)
	switch authType {
	case "auth/psw":
		err = s.loginAuthPsw(username, password, loginDomain, graphCodeFile)
	case "auth/cas":
		err = s.loginAuthCas(foundAuthInfo.LoginURL, loginDomain, casTicket)
	default:
		err = fmt.Errorf("unsupported auth type: %s", authType)
	}
	if err != nil {
		return "", "", nil, err
	}

	err = s.reportEnv()
	if err != nil {
		return "", "", nil, err
	}

	authID, err := s.authCheck()
	if err != nil {
		return "", "", nil, err
	}

	if authID != "" {
		err = s.sendSms(authID)
		if err != nil {
			return "", "", nil, err
		}
		err = s.smsCheckCode(authID)
		if err != nil {
			return "", "", nil, err
		}
	}

	username, err = s.onlineInfo()
	if err != nil {
		return "", "", nil, err
	}

	cookies = make([]Cookie, 0)
	for _, cookie := range s.client.Jar.Cookies(&url.URL{Host: s.baseHost, Scheme: "https"}) {
		if cookie.Name == "sid" {
			sid = cookie.Value
		}

		cookies = append(cookies, Cookie{
			Host:   s.baseHost,
			Scheme: "https",
			Name:   cookie.Name,
			Value:  cookie.Value,
		})
	}

	return username, sid, cookies, nil
}
