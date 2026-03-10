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
	"os"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const (
	UserAgent   = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
	maxAttempts = 5
)

var sharedParams = url.Values{
	"clientType": {"SDPClient"},
	"platform":   {"Linux"},
	"lang":       {"en-US"},
}

func WithSharedParams(extra url.Values) url.Values {
	combined := make(url.Values, len(sharedParams)+len(extra))
	for k, v := range sharedParams {
		combined[k] = append([]string(nil), v...)
	}

	for k, v := range extra {
		for _, val := range v {
			// notice: not Add()
			combined.Set(k, val)
		}
	}

	return combined
}

type Cookie struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type ClientAuthData struct {
	Cookies  []Cookie `json:"cookies"`
	DeviceID string   `json:"device_id"`
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

func (s *Session) withGraphCheckCode(process func(string) (int, error), graphCodeFile string) error {
	graphCheckCodeEnable, err := process("")
	if err != nil {
		return err
	}

	for attempt := 1; graphCheckCodeEnable == 1 && attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("Captcha attempt %d/%d", attempt, maxAttempts)
		}

		imgData, err := s.checkCode()
		if err != nil {
			return err
		}

		_, _, err = s.authConfigInit()
		if err != nil {
			return err
		}

		var graphCheckCode string
		if graphCodeFile != "" {
			if writeErr := os.WriteFile(graphCodeFile, imgData, 0644); writeErr != nil {
				log.Printf("Warning: failed to write graph code image to %s: %v", graphCodeFile, writeErr)
			} else {
				log.Printf("Graph check code saved to %s", graphCodeFile)
			}

			log.Print("Please enter the graph check code JSON: ")
			_, err = fmt.Scanln(&graphCheckCode)
			if err != nil {
				return err
			}
		} else {
			graphCheckCode, err = serveCaptchaInBrowser(imgData, 5*time.Minute)
			if err != nil {
				return fmt.Errorf("failed to get captcha input: %w", err)
			}
		}

		log.DebugPrintf("graphCheckCode submitted: %s", graphCheckCode)

		graphCheckCodeEnable, err = process(graphCheckCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable == 0 {
			return nil
		}

		log.Printf("Captcha verification failed (attempt %d/%d), retrying with new captcha...", attempt, maxAttempts)
	}

	if graphCheckCodeEnable != 0 {
		return fmt.Errorf("captcha verification failed after %d attempts", maxAttempts)
	}
	return nil
}

func (s *Session) GetAuthInfoList() ([]AuthInfo, error) {
	_, list, err := s.authConfigInit()
	return list, err
}

func (s *Session) Login(username, password, phone, loginDomain, authType, deviceId, graphCodeFile, casTicket string, cookies []Cookie) (string, string, []Cookie, error) {
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
		return "", "", nil, fmt.Errorf("auth type/login domain combination not found: auth type: %s, login domain: %s", authType, loginDomain)
	}

	log.Printf("Starting login with auth type: %s, login domain: %s", authType, loginDomain)
	switch authType {
	case "auth/psw":
		err = s.loginAuthPsw(username, password, loginDomain, graphCodeFile)
	case "auth/cas":
		err = s.loginAuthCas(foundAuthInfo.LoginURL, loginDomain, casTicket)
	case "auth/smsCheckCode":
		err = s.loginAuthSmsCheckCode(phone, loginDomain, graphCodeFile)
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
		err = s.authSms(authID)
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
